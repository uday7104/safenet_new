"""Train SafeNet models on real data and report honest metrics.

  python prepare_data.py   # once: builds data/text.csv, data/urls.csv (real public datasets)
  python train.py          # trains + evaluates + saves models/

Evaluation notes
  * Text: test set = REAL messages only (synthetic augmentation is training-only).
  * URL : split is GROUPED by registered domain, so test URLs come from domains never seen in training.
label: 0 = legitimate, 1 = phishing/scam.
"""
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import GroupShuffleSplit, StratifiedKFold, cross_val_predict, train_test_split

from app.features import parse_url, registered_domain
from app.models import URLModel, build_text_model

ROOT = Path(__file__).parent
DATA, MODELS = ROOT / "data", ROOT / "models"
MODELS.mkdir(exist_ok=True)


def metrics(y_true, proba, thr=0.5):
    y_true = np.asarray(y_true)
    pred = (proba >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    fpr, tpr, _ = roc_curve(y_true, proba)
    return {
        "accuracy": round(accuracy_score(y_true, pred), 4),
        "precision": round(precision_score(y_true, pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, pred, zero_division=0), 4),
        "false_positive_rate": round(fp / max(fp + tn, 1), 4),
        "roc_auc": round(roc_auc_score(y_true, proba), 4),
        "pr_auc": round(average_precision_score(y_true, proba), 4),
        "recall_at_1pct_fpr": round(float(np.interp(0.01, fpr, tpr)), 4),
        "test_size": int(len(y_true)),
    }


def main():
    if not (DATA / "text.csv").exists() or not (DATA / "urls.csv").exists():
        import prepare_data
        prepare_data.main()
    report = {}
    t0 = time.time()

    # ---------------- Text ----------------
    t = pd.read_csv(DATA / "text.csv").dropna(subset=["text", "label"])
    if "source" not in t:
        t["source"] = "real"
    real, syn = t[t.source == "real"], t[t.source != "real"]
    r_tr, r_te = train_test_split(real, test_size=0.2, stratify=real["label"], random_state=7)
    train_df = pd.concat([r_tr, syn])
    model = build_text_model().fit(train_df["text"], train_df["label"])
    report["text_model"] = metrics(r_te["label"], model.predict_proba(r_te["text"])[:, 1])
    # 5-fold CV on real data only (augmentation added to each training fold would be better; kept simple)
    skf = StratifiedKFold(5, shuffle=True, random_state=7)
    cv_p = cross_val_predict(build_text_model(), real["text"], real["label"], cv=skf, method="predict_proba")[:, 1]
    cv_f1 = [f1_score(real["label"].iloc[i], (cv_p[i] >= 0.5).astype(int)) for _, i in skf.split(real["text"], real["label"])]
    report["text_model"]["cv_f1_mean"] = round(float(np.mean(cv_f1)), 4)
    report["text_model"]["cv_f1_std"] = round(float(np.std(cv_f1)), 4)
    model = build_text_model().fit(pd.concat([real, syn])["text"], pd.concat([real, syn])["label"])  # final fit on everything
    joblib.dump(model, MODELS / "text_model.joblib")

    # ---------------- URL ----------------
    u = pd.read_csv(DATA / "urls.csv").dropna().drop_duplicates("url")
    groups = u["url"].map(lambda x: registered_domain(parse_url(x)[2]))
    tr, te = next(GroupShuffleSplit(1, test_size=0.2, random_state=7).split(u, u["label"], groups))
    um = URLModel().fit(u["url"].iloc[tr], u["label"].iloc[tr])
    report["url_model"] = metrics(u["label"].iloc[te], um.predict_proba(u["url"].iloc[te])[:, 1])
    report["url_model"]["split"] = "grouped by domain (unseen domains)"
    te_df = u.iloc[te].assign(dom=groups.iloc[te].values, pred=(um.predict_proba(u["url"].iloc[te])[:, 1] >= 0.5).astype(int))
    report["url_model"]["fpr_by_domain_macro"] = round(float(te_df[te_df.label == 0].groupby("dom")["pred"].mean().mean()), 4)
    um = URLModel().fit(u["url"], u["label"])  # final fit on everything
    joblib.dump(um, MODELS / "url_model.joblib")

    report["data"] = {"text_real": int(len(real)), "text_synthetic": int(len(syn)), "urls": int(len(u)),
                      "urls_phishing": int(u["label"].sum())}
    report["train_seconds"] = round(time.time() - t0, 1)
    (MODELS / "metrics.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
