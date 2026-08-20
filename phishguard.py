import tkinter as tk
from tkinter import ttk, messagebox
import re
from urllib.parse import urlparse


# ============================================================
# PHISHGUARD BHARAT
# Regional-Language Phishing Detection MVP
# Single-file Python application
# Uses only Python standard library
# ============================================================


APP_NAME = "PhishGuard Bharat"


# ------------------------------------------------------------
# Detection keywords
# ------------------------------------------------------------

URGENCY_WORDS = [
    # English
    "urgent", "immediately", "immediate", "today", "now",
    "last warning", "final warning", "account will be blocked",
    "account blocked", "verify now", "act now", "expires",

    # Hindi
    "तुरंत", "अभी", "आज", "जल्दी", "खाता बंद", "अकाउंट बंद",
    "सत्यापित", "अंतिम चेतावनी", "तुरन्त",

    # Punjabi
    "ਤੁਰੰਤ", "ਹੁਣੇ", "ਅੱਜ", "ਖਾਤਾ ਬੰਦ", "ਤਸਦੀਕ",
]

OTP_WORDS = [
    "otp", "one time password", "verification code",
    "verification otp", "security code",

    # Hindi
    "ओटीपी", "वन टाइम पासवर्ड", "सत्यापन कोड",

    # Punjabi
    "ਓਟੀਪੀ", "ਵੈਰੀਫਿਕੇਸ਼ਨ ਕੋਡ",
]

KYC_WORDS = [
    "kyc", "e-kyc", "ekyc", "pan card", "aadhaar",
    "aadhar", "update kyc", "kyc update",

    # Hindi
    "केवाईसी", "केवाईसी अपडेट", "आधार", "पैन कार्ड",

    # Punjabi
    "ਕੇਵਾਈਸੀ", "ਆਧਾਰ", "ਪੈਨ ਕਾਰਡ",
]

MONEY_WORDS = [
    "payment", "pay", "refund", "cashback", "reward",
    "prize", "lottery", "money", "bank", "account",
    "transaction", "transfer", "upi", "wallet",

    # Hindi
    "भुगतान", "पैसे", "इनाम", "लॉटरी", "बैंक",
    "खाता", "लेनदेन", "रिफंड",

    # Punjabi
    "ਪੈਸੇ", "ਇਨਾਮ", "ਲਾਟਰੀ", "ਬੈਂਕ", "ਖਾਤਾ",
]

CREDENTIAL_WORDS = [
    "password", "passcode", "pin", "cvv", "card number",
    "account number", "login", "username",

    # Hindi
    "पासवर्ड", "पिन", "सीवीवी", "कार्ड नंबर",
    "खाता नंबर", "लॉगिन",

    # Punjabi
    "ਪਾਸਵਰਡ", "ਪਿਨ", "ਕਾਰਡ ਨੰਬਰ", "ਖਾਤਾ ਨੰਬਰ",
]

IMPERSONATION_WORDS = [
    "sbi", "hdfc", "icici", "axis bank", "paytm",
    "phonepe", "google pay", "gpay", "amazon",
    "flipkart", "income tax", "government", "police",
    "courier", "customs", "bank support", "customer care",

    # Hindi
    "एसबीआई", "एचडीएफसी", "सरकार", "पुलिस", "बैंक",

    # Punjabi
    "ਐਸਬੀਆਈ", "ਬੈਂਕ", "ਸਰਕਾਰ", "ਪੁਲਿਸ",
]

SUSPICIOUS_URL_WORDS = [
    "bit.ly",
    "tinyurl",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "shorturl",
    "tiny.cc",
]


# ------------------------------------------------------------
# Demo messages
# ------------------------------------------------------------

DEMO_MESSAGES = {
    "English Scam": (
        "URGENT! Your SBI account will be blocked today. "
        "Complete KYC immediately by clicking this link "
        "http://bit.ly/account-update and enter your OTP."
    ),

    "Hindi Scam": (
        "तुरंत ध्यान दें! आपका बैंक खाता आज बंद हो जाएगा। "
        "KYC अपडेट करने के लिए अभी इस लिंक पर क्लिक करें "
        "http://bit.ly/kyc-update और अपना OTP दर्ज करें।"
    ),

    "Punjabi Scam": (
        "ਤੁਰੰਤ ਧਿਆਨ ਦਿਓ! ਤੁਹਾਡਾ ਬੈਂਕ ਖਾਤਾ ਅੱਜ ਬੰਦ ਹੋ ਜਾਵੇਗਾ। "
        "KYC ਅਪਡੇਟ ਕਰਨ ਲਈ ਹੁਣੇ ਇਸ ਲਿੰਕ ਤੇ ਕਲਿੱਕ ਕਰੋ "
        "http://bit.ly/kyc ਅਤੇ OTP ਦਿਓ।"
    ),

    "Safe Message": (
        "Your electricity bill is ready. "
        "Please open the official electricity board application "
        "to view your bill. Do not share your OTP or password."
    )
}


# ------------------------------------------------------------
# Language detection
# ------------------------------------------------------------

def detect_language(text):
    hindi_chars = len(re.findall(r"[\u0900-\u097F]", text))
    punjabi_chars = len(re.findall(r"[\u0A00-\u0A7F]", text))

    if punjabi_chars > 2:
        return "Punjabi"

    if hindi_chars > 2:
        return "Hindi"

    return "English / Latin"


# ------------------------------------------------------------
# URL extraction
# ------------------------------------------------------------

def extract_urls(text):
    pattern = r"(https?://[^\s]+|www\.[^\s]+)"
    return re.findall(pattern, text, re.IGNORECASE)


def analyze_url(url):
    reasons = []
    score = 0

    clean_url = url.rstrip(".,!?;:)]}")

    if any(short in clean_url.lower() for short in SUSPICIOUS_URL_WORDS):
        score += 15
        reasons.append(
            "Suspicious URL shortener detected."
        )

    try:
        parsed = urlparse(clean_url)

        domain = parsed.netloc.lower()

        if domain:
            # IP address instead of normal domain
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
                score += 20
                reasons.append(
                    "The link uses an IP address instead of a normal domain."
                )

            # HTTP instead of HTTPS
            if parsed.scheme.lower() == "http":
                score += 8
                reasons.append(
                    "The link does not use HTTPS."
                )

            # Suspicious words in domain
            suspicious_domain_terms = [
                "verify",
                "login",
                "secure",
                "update",
                "account",
                "kyc",
                "reward",
                "claim",
                "bank",
            ]

            found = [
                word for word in suspicious_domain_terms
                if word in domain
            ]

            if found:
                score += 5
                reasons.append(
                    "The domain contains words commonly used in deceptive links."
                )

    except Exception:
        score += 5
        reasons.append("The URL could not be fully parsed.")

    return score, reasons


# ------------------------------------------------------------
# Main phishing analysis
# ------------------------------------------------------------

def analyze_message(text):

    if not text.strip():
        return {
            "score": 0,
            "level": "NO INPUT",
            "language": "Unknown",
            "reasons": [],
            "urls": [],
            "actions": []
        }

    lower = text.lower()

    score = 0
    reasons = []
    urls = extract_urls(text)

    # Language
    language = detect_language(text)

    # ----------------------------------------
    # Urgency
    # ----------------------------------------

    urgency_found = []

    for word in URGENCY_WORDS:
        if word.lower() in lower:
            urgency_found.append(word)

    if urgency_found:
        score += 20
        reasons.append(
            "Urgency or threat language detected."
        )

    # ----------------------------------------
    # OTP
    # ----------------------------------------

    otp_found = []

    for word in OTP_WORDS:
        if word.lower() in lower:
            otp_found.append(word)

    if otp_found:
        score += 25
        reasons.append(
            "The message requests or refers to an OTP/verification code."
        )

    # ----------------------------------------
    # KYC
    # ----------------------------------------

    kyc_found = []

    for word in KYC_WORDS:
        if word.lower() in lower:
            kyc_found.append(word)

    if kyc_found:
        score += 15
        reasons.append(
            "KYC or identity-verification language detected."
        )

    # ----------------------------------------
    # Credentials
    # ----------------------------------------

    credential_found = []

    for word in CREDENTIAL_WORDS:
        if word.lower() in lower:
            credential_found.append(word)

    if credential_found:
        score += 20
        reasons.append(
            "The message requests or refers to sensitive credentials."
        )

    # ----------------------------------------
    # Money / financial terms
    # ----------------------------------------

    money_found = []

    for word in MONEY_WORDS:
        if word.lower() in lower:
            money_found.append(word)

    if money_found:
        score += 10
        reasons.append(
            "Financial or payment-related language detected."
        )

    # ----------------------------------------
    # Impersonation
    # ----------------------------------------

    impersonation_found = []

    for word in IMPERSONATION_WORDS:
        if word.lower() in lower:
            impersonation_found.append(word)

    if impersonation_found:
        score += 12
        reasons.append(
            "The message appears to reference a bank, company, government "
            "service or other organization."
        )

    # ----------------------------------------
    # URLs
    # ----------------------------------------

    for url in urls:
        url_score, url_reasons = analyze_url(url)

        score += url_score
        reasons.extend(url_reasons)

    # ----------------------------------------
    # Generic link detection
    # ----------------------------------------

    if urls:
        score += 5
        reasons.append(
            "A clickable external link is present."
        )

    # ----------------------------------------
    # Clamp score
    # ----------------------------------------

    score = min(score, 100)

    # ----------------------------------------
    # Risk level
    # ----------------------------------------

    if score >= 70:
        level = "HIGH RISK"

    elif score >= 40:
        level = "MEDIUM RISK"

    elif score >= 20:
        level = "LOW RISK"

    else:
        level = "NO STRONG PHISHING SIGNAL"

    # ----------------------------------------
    # Remove duplicate reasons
    # ----------------------------------------

    unique_reasons = []

    for reason in reasons:
        if reason not in unique_reasons:
            unique_reasons.append(reason)

    # ----------------------------------------
    # Safety actions
    # ----------------------------------------

    actions = [
        "Do not click suspicious links.",
        "Do not share OTP, password, PIN or CVV.",
        "Verify the request through the organization's official app or website.",
    ]

    if urls:
        actions.append(
            "Avoid opening the detected external link until it is verified."
        )

    return {
        "score": score,
        "level": level,
        "language": language,
        "reasons": unique_reasons,
        "urls": urls,
        "actions": actions
    }


# ------------------------------------------------------------
# GUI
# ------------------------------------------------------------

class PhishGuardApp:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "PhishGuard Bharat - Regional Phishing Detection"
        )

        self.root.geometry("1050x720")

        self.root.configure(
            bg="#F4F7FA"
        )

        self.create_styles()
        self.create_interface()

    # --------------------------------------------------------
    # Styles
    # --------------------------------------------------------

    def create_styles(self):

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except:
            pass

        style.configure(
            "TButton",
            font=("Arial", 11),
            padding=8
        )

        style.configure(
            "TCombobox",
            font=("Arial", 10)
        )

    # --------------------------------------------------------
    # Interface
    # --------------------------------------------------------

    def create_interface(self):

        # Header
        header = tk.Frame(
            self.root,
            bg="#16324F",
            height=90
        )

        header.pack(
            fill="x"
        )

        title = tk.Label(
            header,
            text="🛡  PhishGuard Bharat",
            font=("Arial", 24, "bold"),
            fg="white",
            bg="#16324F"
        )

        title.pack(
            pady=(15, 2)
        )

        subtitle = tk.Label(
            header,
            text="Regional-language phishing detection & digital safety",
            font=("Arial", 11),
            fg="#D8E8F4",
            bg="#16324F"
        )

        subtitle.pack()

        # Main container
        main = tk.Frame(
            self.root,
            bg="#F4F7FA"
        )

        main.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=20
        )

        # Left side
        left = tk.Frame(
            main,
            bg="white",
            bd=1,
            relief="solid"
        )

        left.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 10)
        )

        input_title = tk.Label(
            left,
            text="Paste suspicious message",
            font=("Arial", 15, "bold"),
            fg="#16324F",
            bg="white"
        )

        input_title.pack(
            anchor="w",
            padx=18,
            pady=(18, 8)
        )

        self.message_box = tk.Text(
            left,
            height=15,
            wrap="word",
            font=("Arial", 11),
            bg="#FBFCFD",
            fg="#26343F",
            relief="solid",
            bd=1
        )

        self.message_box.pack(
            fill="both",
            expand=True,
            padx=18,
            pady=5
        )

        # Buttons
        button_frame = tk.Frame(
            left,
            bg="white"
        )

        button_frame.pack(
            fill="x",
            padx=18,
            pady=15
        )

        analyze_button = tk.Button(
            button_frame,
            text="🔍  ANALYZE MESSAGE",
            command=self.analyze,
            font=("Arial", 11, "bold"),
            bg="#236B8E",
            fg="white",
            activebackground="#1B536F",
            activeforeground="white",
            relief="flat",
            padx=15,
            pady=10
        )

        analyze_button.pack(
            side="left"
        )

        clear_button = tk.Button(
            button_frame,
            text="Clear",
            command=self.clear,
            font=("Arial", 10),
            bg="#E8EDF1",
            fg="#26343F",
            relief="flat",
            padx=15,
            pady=10
        )

        clear_button.pack(
            side="left",
            padx=8
        )

        # Demo dropdown
        demo_frame = tk.Frame(
            left,
            bg="white"
        )

        demo_frame.pack(
            fill="x",
            padx=18,
            pady=(0, 18)
        )

        tk.Label(
            demo_frame,
            text="Demo message:",
            font=("Arial", 9),
            fg="#687681",
            bg="white"
        ).pack(
            side="left"
        )

        self.demo_var = tk.StringVar()

        self.demo_box = ttk.Combobox(
            demo_frame,
            textvariable=self.demo_var,
            values=list(DEMO_MESSAGES.keys()),
            state="readonly",
            width=25
        )

        self.demo_box.pack(
            side="left",
            padx=8
        )

        self.demo_box.bind(
            "<<ComboboxSelected>>",
            self.load_demo
        )

        # Right side
        right = tk.Frame(
            main,
            bg="white",
            bd=1,
            relief="solid",
            width=380
        )

        right.pack(
            side="right",
            fill="both",
            padx=(10, 0)
        )

        right.pack_propagate(False)

        result_title = tk.Label(
            right,
            text="Analysis Result",
            font=("Arial", 15, "bold"),
            fg="#16324F",
            bg="white"
        )

        result_title.pack(
            anchor="w",
            padx=18,
            pady=(18, 10)
        )

        # Score
        self.score_label = tk.Label(