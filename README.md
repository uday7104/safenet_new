# SafeNet: scam & phishing checker (database-comparison version)

SafeNet compares a **sender email, message and link** with reference data stored in **MongoDB** and scores the risk from the
matches. **Nothing is trained**: every point of the score has a named reason you can show.

## How it works
```
email + message + link ─► app/engine.py ─► compare with MongoDB collections ─► evidence list ─► score, level, advice
```
| Collection | What it holds | Used for |
|---|---|---|
| `known_urls` | known phishing links (exact link, host, domain) | exact / same-website / same-domain match |
| `trusted_domains` | top-10,000 websites | lowers a link's risk (warning signs count x0.25) |
| `blocked_senders` | blocked addresses/domains, disposable email services | sender checks |
| `phrases` | scam wording patterns with category and weight | message scoring |
| `brands` | brand names, look-alike keywords, their REAL domains | spoof detection (paypa1, hdfc-secure...) |
| `known_messages` | scam and normal messages | similarity to known scams |
| `suspicious_tlds`, `shorteners`, `free_email` | small lists | structural warning signs |
| `analyses` | one record per check (history) | review / export |

**Scoring.** Each match has a weight 0-1. Evidence is combined as `risk = 1 - (1-w1)(1-w2)...`, separately for message, link and
sender, then once more across the three. Levels: Low < 35, Medium 35-65, High > 65.
Examples: exact match with a known phishing link = 0.99; look-alike brand domain = 0.75; "verify your password" = 0.65;
suspicious ending such as .xyz = 0.3; weak impersonation word = 0.08.

**Improving it = adding records**, not retraining. Report a scam (admin):
`POST /reference/blacklist {"kind":"url|domain|email","value":"...","note":"..."}` or edit the collections in Atlas/Compass.

## Run locally
```powershell
python -m pip install -r requirements.txt
$env:MONGODB_URI="mongodb+srv://USER:PASSWORD@cluster.xxxx.mongodb.net/"   # skip for a local MongoDB
python -m uvicorn app.main:app --reload
```
On first start the empty reference collections are filled automatically (about 20,000 phishing links, 10,000 trusted domains,
5,200 messages, phrases, brands). Manual: `python seed_db.py` (`--reset` to rebuild, `--full` to add the large live feed if you
download `data/raw/phish_active.txt`). Open http://127.0.0.1:8000.

**MongoDB options:** Atlas free M0 cluster (recommended, also for deployment) | `docker compose up -d` | local MongoDB Community.
Variables: `MONGODB_URI` (default `mongodb://localhost:27017`), `MONGODB_DB` (default `safenet`), `ADMIN_TOKEN`, `AUTO_SEED` (default 1).

If MongoDB is unreachable the checker still works using only the small built-in lists (no known-phishing-link or trusted-domain
data, so less accurate), nothing is saved, and checks are a few seconds slower.

## API
| Endpoint | Purpose |
|---|---|
| `POST /analyze` `{text, url, email}` (any one or more) | full result with `evidence`, `signals`, per-link and per-email details |
| `GET /stats` | sizes of the reference collections (public) |
| `GET /history`, `/history/summary`, `/history/{id}`, `DELETE /history/{id}`, `/history/export.csv` | stored checks (admin) |
| `POST /reference/blacklist` | add a scam link/domain/sender (admin) |

Admin = header `X-Admin-Token: <ADMIN_TOKEN>`; with no token set, only `localhost` is allowed. History page: `/static/history.html`.

## Deploy (Render + Atlas)
Push to GitHub, Render > New > Blueprint. Set `MONGODB_URI` when asked (allow `0.0.0.0/0` in Atlas Network Access). `ADMIN_TOKEN`
is generated for you (Render > Environment). The reference data is seeded on the first start; the history persists in Atlas.

## Tests
`pip install -r requirements-dev.txt && pytest -q` (in-memory MongoDB stand-in, no server needed).

## Files
`app/engine.py` (all scoring logic) | `app/reference.py` (loads/looks up reference data) | `app/reference_data.py` (built-in lists,
phrases, brands) | `app/seed.py` + `seed_db.py` (fill MongoDB) | `app/db.py` (history + collection access) | `app/main.py` (API) |
`static/index.html`, `static/history.html` (UI) | `data/*.csv`, `data/trusted_domains.txt` (seed sources).

**Optional ML experiments (not used by the app):** `train.py`, `prepare_data.py`, `app/models.py`, `app/make_sample_data.py`,
`requirements-ml.txt`.

## Limits
Only as good as its data: a brand-new scam on an unknown domain with clean wording will not match anything. Sample links and
messages come from public datasets (Phishing.Database, SMS Spam Collection); keep adding records. Message similarity is simple word
overlap. A link that is clean today may be malicious tomorrow; trusted domains are not guaranteed safe. Checks (including message
text) are stored: do not paste passwords or private details, and tell users their checks are saved.
