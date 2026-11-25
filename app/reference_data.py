"""Built-in reference data. `seed_db.py` copies it into MongoDB (where you can edit it); it is also the
fallback when the database is unreachable. Weights are 0-1 'how suspicious is this on its own'."""

U, C, M, T, A, P = ("Urgency", "Credential request", "Money / reward lure", "Threat / fear",
                    "Authority impersonation", "Payment request")

PHRASES = [  # (regex, category, weight)
    # Urgency
    (r"\burgent(ly)?\b", U, .25), (r"\bimmediately\b", U, .25), (r"\basap\b", U, .2),
    (r"\bwithin \d+ ?(hours?|hrs?|minutes?|mins?|days?)\b", U, .3), (r"\blast chance\b", U, .25),
    (r"\bfinal (notice|warning|reminder)\b", U, .3), (r"\bact now\b", U, .3), (r"\btoday only\b", U, .25),
    (r"\b(expires?|expiring) (today|soon|in \d+)", U, .25), (r"\blimited time\b", U, .2), (r"\bright away\b", U, .15),
    (r"\bdon'?t (delay|ignore)\b", U, .2), (r"\bfailure to (comply|respond|verify)\b", U, .35),
    # Credential requests
    (r"\b(verify|confirm|validate|update|re-?activate|secure) your (account|password|identity|details|information|bank|card|kyc|pan|aadhaar|login|email|payment)", C, .55),
    (r"\b(enter|share|send|provide|submit|reply with|give|tell) (us |me )?(your |the )?(otp|one[- ]time password|pin|cvv|password|passcode|card number|account number|ssn|aadhaar|pan( card)?|net ?banking)\b", C, .65),
    (r"\b(log ?in|sign ?in) (to|at|here) (verify|confirm|secure|unlock|restore|update|avoid)", C, .5),
    (r"\bclick (here|the link|below|this link) to (verify|confirm|log ?in|sign ?in|unlock|claim|update|restore|avoid)", C, .5),
    (r"\bkyc\b.{0,40}\b(update|expire|incomplete|pending|verify|blocked)|\b(update|complete|verify).{0,20}\bkyc\b", C, .55),
    (r"\bunusual (sign[- ]?in|log ?in|activity)\b", C, .4), (r"\bsecurity alert\b", C, .3), (r"\bpassword (will )?expire", C, .4),
    # Money / reward lures
    (r"\b(you('ve| have)? (just )?won|you are (a )?winner|you('ve| have) been selected)\b", M, .5), (r"\bcongratulations\b", M, .2),
    (r"\bclaim (your |the |now )?(free )?(prize|reward|gift|refund|cash ?back|bonus|winnings)", M, .5),
    (r"\b(lottery|jackpot|sweepstakes?)\b", M, .45), (r"\bfree (gift|iphone|cash|recharge|data|vouchers?|money)\b", M, .4),
    (r"\bcash ?prize\b", M, .45), (r"[$₹£€]\s?\d[\d,]*(\.\d+)? (gift card|prize|reward|cash ?back|bonus|voucher)", M, .5),
    (r"\b(double|triple|10x) your (money|investment|income)\b", M, .6), (r"\bguaranteed (returns?|profit|income)\b", M, .55),
    (r"\b(crypto|bitcoin) (giveaway|investment|doubler)\b", M, .5), (r"\bwork from home\b.{0,40}\b(earn|income|\$|₹)", M, .4),
    (r"\bpending refund\b|\brefund (is )?(ready|pending|waiting)\b|\btax refund\b", M, .4),
    (r"\binheritance\b|\bbeneficiary\b.{0,30}\bfunds?\b", M, .5),
    # Threats
    (r"\b(account|card|sim|number|service|mailbox|wallet) (has been |will be |is |was )?(suspended|blocked|locked|terminated|deactivated|disabled|closed|disconnected|frozen)\b", T, .45),
    (r"\bunauthori[sz]ed (access|login|transaction|attempt)\b", T, .4),
    (r"\blegal action\b|\barrest\b|\bwarrant\b|\bfine of\b|\bpenalty\b|\bprosecut", T, .4),
    (r"\byour account (is |has been )?(compromised|hacked|at risk)\b", T, .45),
    (r"\b(will|may) be (blocked|suspended|terminated|disabled|deactivated|disconnected|closed)\b", T, .4),
    # Payment requests
    (r"\bpay (the |a |your )?(small )?(customs|delivery|redelivery|processing|release|clearance|shipping|handling|registration) (fee|charges?)\b", P, .55),
    (r"\b(send|transfer|wire) (me |us )?(money|funds|gift cards?|bitcoin|crypto|payment)\b", P, .5),
    (r"\b(western union|moneygram|wire transfer)\b", P, .4), (r"\b(processing|advance|registration|release) fee\b", P, .45),
    (r"\bupi (pin|request|collect)\b|\bscan (the |this )?qr( code)?\b", P, .4),
    (r"\bgift cards?\b.{0,30}\b(buy|purchase|send|code|scratch)\b|\b(buy|purchase).{0,20}\bgift cards?\b", P, .55),
    # Impersonation (weak on its own)
    (r"\b(paypal|amazon|microsoft|apple id|icloud|netflix|hdfc|icici|sbi|axis bank|paytm|phonepe|bank|income tax|irs|customs|courier|dhl|fedex|hr department|it support|helpdesk|help desk|police|cbi)\b", A, .08),
    (r"\bdear (customer|user|client|member|account holder|sir/?madam)\b", A, .15),
]

# keywords = tokens looked for in domains; mentions = words looked for in message text; domains = the REAL websites
BRANDS = [
    {"name": "PayPal", "keywords": ["paypal"], "mentions": ["paypal"], "domains": ["paypal.com", "paypal.me"]},
    {"name": "Amazon", "keywords": ["amazon"], "mentions": ["amazon"], "domains": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amzn.to", "amzn.in", "primevideo.com"]},
    {"name": "Microsoft", "keywords": ["microsoft", "office365", "outlook"], "mentions": ["microsoft", "office 365", "outlook"], "domains": ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "xbox.com", "office365.com"]},
    {"name": "Apple", "keywords": ["appleid", "icloud", "apple"], "mentions": ["apple id", "appleid", "icloud", "apple support"], "domains": ["apple.com", "icloud.com"]},
    {"name": "Google", "keywords": ["google", "gmail"], "mentions": ["google account", "gmail account", "google pay"], "domains": ["google.com", "gmail.com", "youtube.com", "goo.gl", "google.co.in", "withgoogle.com"]},
    {"name": "Meta", "keywords": ["facebook", "instagram", "whatsapp"], "mentions": ["facebook", "instagram", "whatsapp"], "domains": ["facebook.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com", "fb.me"]},
    {"name": "Netflix", "keywords": ["netflix"], "mentions": ["netflix"], "domains": ["netflix.com"]},
    {"name": "HDFC Bank", "keywords": ["hdfc", "hdfcbank"], "mentions": ["hdfc"], "domains": ["hdfcbank.com", "hdfc.com", "hdfcbank.net", "hdfclife.com"]},
    {"name": "ICICI Bank", "keywords": ["icici", "icicibank"], "mentions": ["icici"], "domains": ["icicibank.com", "icicidirect.com", "icicilombard.com"]},
    {"name": "State Bank of India", "keywords": ["sbi", "onlinesbi"], "mentions": ["sbi", "state bank of india"], "domains": ["sbi.co.in", "onlinesbi.com", "sbicard.com", "onlinesbi.sbi", "sbi.bank.in"]},
    {"name": "Axis Bank", "keywords": ["axisbank"], "mentions": ["axis bank"], "domains": ["axisbank.com"]},
    {"name": "Paytm", "keywords": ["paytm"], "mentions": ["paytm"], "domains": ["paytm.com", "paytmbank.com"]},
    {"name": "PhonePe", "keywords": ["phonepe"], "mentions": ["phonepe"], "domains": ["phonepe.com"]},
    {"name": "Chase", "keywords": ["chase"], "mentions": ["chase bank"], "domains": ["chase.com"]},
    {"name": "Wells Fargo", "keywords": ["wellsfargo"], "mentions": ["wells fargo"], "domains": ["wellsfargo.com"]},
    {"name": "Bank of America", "keywords": ["bankofamerica"], "mentions": ["bank of america"], "domains": ["bankofamerica.com"]},
    {"name": "DHL", "keywords": ["dhl"], "mentions": ["dhl"], "domains": ["dhl.com", "dhl.de"]},
    {"name": "FedEx", "keywords": ["fedex"], "mentions": ["fedex"], "domains": ["fedex.com"]},
    {"name": "UPS", "keywords": ["ups"], "mentions": ["ups parcel", "ups delivery"], "domains": ["ups.com"]},
    {"name": "LinkedIn", "keywords": ["linkedin"], "mentions": ["linkedin"], "domains": ["linkedin.com", "lnkd.in"]},
]

SUSPICIOUS_TLDS = {"xyz": .3, "top": .3, "tk": .35, "ml": .35, "ga": .35, "cf": .35, "gq": .35, "click": .3, "link": .25,
                   "work": .25, "support": .3, "zip": .3, "country": .3, "kim": .3, "loan": .35, "icu": .3, "buzz": .3,
                   "cyou": .3, "rest": .3, "monster": .3, "site": .2, "online": .2, "live": .15, "club": .2, "cam": .3, "sbs": .3}
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at", "tiny.cc", "buff.ly"]
FREE_EMAIL = ["gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com", "live.com", "aol.com", "proton.me",
              "protonmail.com", "icloud.com", "rediffmail.com", "mail.com", "gmx.com", "zoho.com"]
DISPOSABLE_EMAIL = ["mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org", "yopmail.com",
                    "trashmail.com", "throwawaymail.com", "getnada.com", "sharklasers.com", "maildrop.cc", "dispostable.com", "fakeinbox.com"]

KNOWN_SCAM_MESSAGES = [  # (text, category)
    ("URGENT: Your bank account has been suspended. Verify your password immediately to restore access", "bank phishing"),
    ("Dear customer, your account will be blocked today. Update your KYC details now to avoid suspension", "KYC scam"),
    ("Your KYC is incomplete and your account will be blocked within 24 hours. Click the link to update PAN details", "KYC scam"),
    ("We detected unusual sign-in activity on your account. Confirm your identity or your account will be locked", "account phishing"),
    ("Congratulations! You have won a gift card. Claim your prize now by clicking the link", "prize scam"),
    ("You have been selected as a lucky winner of our lottery. Send your bank details to claim the cash prize", "lottery scam"),
    ("Your package could not be delivered. Pay the small redelivery fee at the link or it will be returned", "delivery scam"),
    ("Your parcel is held at customs. Pay the customs fee today to release your package", "delivery scam"),
    ("Your tax refund is ready. Verify your identity and bank details to receive your refund", "refund scam"),
    ("You have a pending refund. Log in to confirm your card number and claim it today only", "refund scam"),
    ("Your mailbox is full. Sign in to verify your account within 2 hours to avoid deactivation", "email phishing"),
    ("IT support: your password expires today. Click here to keep the same password", "email phishing"),
    ("Security alert: unauthorized access to your account. Update your password now to secure your account", "account phishing"),
    ("Earn double your money with our crypto investment. Guaranteed returns, limited time bonus", "investment scam"),
    ("Work from home and earn 5000 daily. No experience needed. Pay a small registration fee to start", "job scam"),
    ("Hello I am a prince and need your help to transfer funds. You will receive a share as reward", "advance-fee scam"),
    ("Your electricity will be disconnected tonight unless you pay the pending bill. Call this number immediately", "utility scam"),
    ("Your SIM will be blocked in 24 hours. Complete verification by sharing the OTP you received", "OTP scam"),
    ("Reply with the OTP you just received to confirm your delivery address", "OTP scam"),
    ("Your Netflix subscription payment failed. Update your billing information to avoid cancellation", "subscription phishing"),
    ("We have blocked your debit card due to suspicious activity. Call now and share your card number to unblock", "card scam"),
    ("Final notice: legal action will be taken against you. Pay the penalty immediately", "threat scam"),
    ("Your account has been compromised. Scan the QR code to receive your money back", "payment scam"),
    ("Buy gift cards worth 500 and send me the codes. I am in a meeting and cannot talk", "gift card scam"),
]
KNOWN_SAFE_MESSAGES = [
    "Hi, are we still meeting for lunch tomorrow at one?", "Your order has shipped and will arrive on Friday. Thanks for shopping with us",
    "Reminder: team standup tomorrow at 9am. Agenda attached", "Thanks for your payment. Your receipt is attached to this email",
    "Can you review my pull request when you get a chance?", "Happy birthday! Hope you have a great day",
    "Your appointment is confirmed for Monday at 4pm. Reply to reschedule", "Your OTP for the transaction is 482913. Do not share it with anyone",
    "The meeting minutes are attached. Let me know if I missed anything", "Class notes for today's lecture are uploaded on the portal",
    "Dinner is at seven, don't be late", "Your package is out for delivery today. No action is needed",
]
