"""Builds data/text.csv, data/urls.csv and data/trusted_domains.txt from public datasets.

Sources (all downloaded from GitHub raw):
  - SMS Spam Collection (UCI, CC BY 4.0)            -> real text, ham/spam
  - Phishing.Database ACTIVE links (MIT)             -> real phishing URLs
  - Benign URL list (UNB/ISCX-style benign set)      -> real legitimate URLs
  - Top-10,000 domains list                          -> legit root domains + trusted-domain list

Run:  python prepare_data.py          (downloads ~70 MB once into data/raw/, then builds the CSVs)
"""
import random
import urllib.request
from collections import defaultdict
from pathlib import Path

import pandas as pd

from app.features import normalize_url, parse_url, registered_domain
from app.make_sample_data import synthetic_text

ROOT = Path(__file__).parent
RAW, DATA = ROOT / "data" / "raw", ROOT / "data"
RAW.mkdir(parents=True, exist_ok=True)

SOURCES = {
    "sms.tsv": "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv",
    "phish_active.txt": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "benign.csv": "https://raw.githubusercontent.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/master/DataFiles/1.Benign_list_big_final.csv",
    "top10k.txt": "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-10000-domains",
}
N_PER_CLASS = 20000
CAP = {"phish": 25, "benign": 120}
rng = random.Random(42)


def download():
    for name, url in SOURCES.items():
        if not (RAW / name).exists():
            print("Downloading", name)
            urllib.request.urlretrieve(url, RAW / name)


def lines(name):
    return [l.strip() for l in (RAW / name).read_text(errors="ignore").splitlines() if l.strip()]


def clean_urls(urls):
    out, seen = [], set()
    for u in urls:
        if len(u) > 300 or " " in u:
            continue
        key = normalize_url(u)
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out


def sample_capped(urls, n, cap):
    """Random sample with a per-registered-domain cap, so a few domains can't dominate."""
    rng.shuffle(urls)
    per, picked = defaultdict(int), []
    for u in urls:
        d = registered_domain(parse_url(u)[2])
        if per[d] < cap:
            per[d] += 1
            picked.append(u)
            if len(picked) >= n:
                break
    return picked


def main():
    download()

    top = lines("top10k.txt")
    (DATA / "trusted_domains.txt").write_text("\n".join(d.lower() for d in top))

    phish = sample_capped(clean_urls(lines("phish_active.txt")), N_PER_CLASS, CAP["phish"])
    benign = sample_capped(clean_urls(lines("benign.csv")), N_PER_CLASS, CAP["benign"])
    roots = [rng.choice(["https://", "https://www."]) + d for d in top[:5000]]
    benign += roots
    rows = [(u, 1) for u in phish] + [(u, 0) for u in benign]
    urls = pd.DataFrame(rows, columns=["url", "label"])
    urls["key"] = urls["url"].map(normalize_url)
    urls = urls.drop_duplicates("key").drop(columns="key").sample(frac=1, random_state=1)
    urls.to_csv(DATA / "urls.csv", index=False)
    print("urls.csv:", urls["label"].value_counts().to_dict())

    sms = pd.read_csv(RAW / "sms.tsv", sep="\t", header=None, names=["label", "text"])
    sms["label"] = (sms["label"] == "spam").astype(int)
    sms["source"] = "real"
    syn = pd.DataFrame(synthetic_text(250, phish_urls=phish[:500]), columns=["text", "label"])
    syn["source"] = "synthetic"
    text = pd.concat([sms[["text", "label", "source"]], syn]).drop_duplicates("text").sample(frac=1, random_state=1)
    text.to_csv(DATA / "text.csv", index=False)
    print("text.csv:", text.groupby(["source", "label"]).size().to_dict())


if __name__ == "__main__":
    main()
