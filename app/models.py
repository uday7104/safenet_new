"""Model classes (kept in a module so joblib can load them)."""
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, make_pipeline
from sklearn.preprocessing import FunctionTransformer

from sklearn.model_selection import GroupKFold

from .features import parse_url, registered_domain, strip_urls, url_features


def _strip(X):
    return [strip_urls(x) for x in X]


def build_text_model():
    """Word + character TF-IDF -> calibrated logistic regression."""
    feats = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, strip_accents="unicode")),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=3, sublinear_tf=True, max_features=150000)),
    ])
    clf = CalibratedClassifierCV(LogisticRegression(max_iter=2000, class_weight="balanced", C=4.0), method="sigmoid", cv=5)
    # URLs are removed first: the text model judges wording, the URL model judges links.
    return make_pipeline(FunctionTransformer(_strip), feats, clf)


class URLModel:
    """Calibrated gradient boosting on lexical URL features.

    Why no character n-grams: on unseen domains they memorise domain names and RAISE false positives.
    The decision threshold is tuned on held-out DOMAINS to hit `target_fpr`, then probabilities are
    re-centred so that 0.5 == that operating point (keeps fusion thresholds meaningful).
    """

    def __init__(self, target_fpr=0.02):
        self.target_fpr = target_fpr
        self.thr = 0.5
        self.model = None

    def _make(self):
        gb = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.05, max_leaf_nodes=15,
                                            l2_regularization=1.0, class_weight="balanced", random_state=7)
        return CalibratedClassifierCV(gb, method="isotonic", cv=3)

    @staticmethod
    def _lex(urls):
        return np.array([url_features(u) for u in urls], dtype=float)

    def _raw(self, X):
        return self.model.predict_proba(X)[:, 1]

    def fit(self, urls, y):
        urls, y = list(urls), np.asarray(y)
        X = self._lex(urls)
        groups = np.array([registered_domain(parse_url(u)[2]) for u in urls])
        # Out-of-fold scores on UNSEEN domains -> threshold where domain-weighted FPR == target_fpr.
        oof = np.zeros(len(y))
        for tr, va in GroupKFold(4).split(X, y, groups):
            oof[va] = self._make().fit(X[tr], y[tr]).predict_proba(X[va])[:, 1]
        neg = y == 0
        _, inv, cnt = np.unique(groups[neg], return_inverse=True, return_counts=True)
        w = 1.0 / cnt[inv]                      # each benign domain counts equally
        order = np.argsort(oof[neg])
        cum = np.cumsum(w[order]) / w.sum()
        self.thr = float(np.clip(oof[neg][order][np.searchsorted(cum, 1 - self.target_fpr)], 0.05, 0.95))
        self.model = self._make().fit(X, y)     # final fit on all data
        return self

    def predict_proba(self, urls):
        p = np.clip(self._raw(self._lex(list(urls))), 1e-4, 1 - 1e-4)
        logit = np.log(p / (1 - p)) - np.log(self.thr / (1 - self.thr))
        q = 1 / (1 + np.exp(-logit))
        return np.column_stack([1 - q, q])

    def predict(self, urls):
        return (self.predict_proba(urls)[:, 1] >= 0.5).astype(int)
