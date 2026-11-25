"""Fill MongoDB with SafeNet's reference data.  python seed_db.py [--reset] [--full]"""
import argparse

from app import db
from app.seed import seed

ap = argparse.ArgumentParser()
ap.add_argument("--reset", action="store_true", help="drop and refill all reference collections")
ap.add_argument("--full", action="store_true", help="also load data/raw/phish_active.txt if present")
a = ap.parse_args()
db.init_db()
print("Seeded:", seed(reset=a.reset, full=a.full) or "nothing to do (already filled; use --reset to rebuild)")
