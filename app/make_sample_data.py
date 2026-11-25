"""Synthetic text generator, used ONLY to augment training with credential-phishing / transactional-ham
patterns missing from the public SMS dataset. Never used for evaluation."""
import random

legit_t = [
    "Hi {n}, are we still meeting for lunch at {t}?", "Your order #{o} has been shipped and will arrive on Friday.",
    "Reminder: team standup tomorrow at {t}. Agenda attached.", "Thanks for your payment. Your receipt for invoice {o} is attached.",
    "Can you review my pull request when you get a chance?", "Happy birthday {n}! Hope you have a great day.",
    "The quarterly report is ready. Let me know if you have questions.", "Your appointment is confirmed for Monday at {t}.",
    "Class notes for today's lecture are uploaded to the portal.", "Mom: dinner is at {t}, don't be late!",
    "Your OTP for the transaction is {o}. Do not share it with anyone. - Bank", "Please find the meeting minutes attached.",
    "Your {b} order #{o} has shipped. Track it in the official app.", "Your {b} receipt for {o} is attached. Thanks for your purchase.",
    "Hi {n}, your interview is scheduled for {t} tomorrow. Please confirm by replying yes.",
    "Your package is out for delivery today. No action needed.", "Meeting moved to {t}, same room as before.",
]
phish_t = [
    "URGENT: Your {b} account has been suspended. Verify your password immediately at {u}",
    "Dear customer, unusual login detected. Confirm your account details within 24 hours: {u}",
    "Congratulations {n}! You have won a $1000 gift card. Claim your prize now: {u}",
    "Final notice: your bank account is locked. Click {u} and enter your card number and PIN to unlock.",
    "You have a pending refund of $450. Login to {u} to claim it today only.",
    "Your package could not be delivered. Pay the customs fee at {u} or it will be returned.",
    "IT Support: your mailbox is full. Sign in at {u} to avoid deactivation within 2 hours.",
    "Earn double your money with our crypto investment. Limited time bonus, register: {u}",
    "Security alert: unauthorized access to your {b} account. Update your password now {u}",
    "Hello, I am a prince and need your help transferring funds. Send your bank details and get 20% reward.",
    "Your tax refund is ready. Verify your identity and SSN at {u} immediately.",
    "WINNER!! Free cash prize waiting. Reply with your OTP to claim your reward now.",
    "{b}: your KYC is incomplete and your account will be blocked today. Update PAN details here {u}",
    "Your {b} subscription payment failed. Update your billing information at {u} to avoid cancellation.",
]
names = ["Aman", "Riya", "Sam", "Priya", "John", "Neha", "Uday", "Karan"]
brands = ["PayPal", "Amazon", "Microsoft", "HDFC Bank", "Apple", "Netflix", "SBI", "Paytm"]
times = ["1pm", "9am", "4:30pm", "6pm"]


def _fill(tpl, u=""):
    return tpl.format(n=random.choice(names), t=random.choice(times), o=random.randint(1000, 99999), b=random.choice(brands), u=u)


def synthetic_text(n_each=250, phish_urls=None, seed=42):
    random.seed(seed)
    rows = []
    for _ in range(n_each):
        rows.append((_fill(random.choice(legit_t)), 0))
        u = random.choice(phish_urls) if phish_urls and random.random() < 0.7 else "bit.ly/3xYz"
        rows.append((_fill(random.choice(phish_t), u=u), 1))
    return rows
