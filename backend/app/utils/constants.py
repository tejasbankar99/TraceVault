"""
TraceVault — constants.py
Shared constants for threat classification, IOC typing, authentication verdicts,
brand/TLD/ASN reference data, and keyword lists used across all analysis services.
"""

from __future__ import annotations

import ipaddress

# ---------------------------------------------------------------------------
# Threat classification
# ---------------------------------------------------------------------------

THREAT_CATEGORIES: list[str] = [
    "phishing",
    "impersonation",
    "bec",                   # Business Email Compromise
    "credential_theft",
    "social_engineering",
    "malware_delivery",
    "financial_fraud",
    "benign",
]

# ---------------------------------------------------------------------------
# Severity levels  —  (min_score_inclusive, max_score_inclusive)
# ---------------------------------------------------------------------------

SEVERITY_LEVELS: dict[str, tuple[int, int]] = {
    "CRITICAL": (80, 100),
    "HIGH":     (60, 79),
    "MEDIUM":   (40, 59),
    "LOW":      (20, 39),
    "BENIGN":   (0,  19),
}


def severity_from_score(score: int) -> str:
    """Return the SEVERITY_LEVELS key that contains *score*."""
    for label, (lo, hi) in SEVERITY_LEVELS.items():
        if lo <= score <= hi:
            return label
    return "BENIGN"


# ---------------------------------------------------------------------------
# IOC types
# ---------------------------------------------------------------------------

class IOC_TYPES:
    IP          = "IP"
    DOMAIN      = "DOMAIN"
    URL         = "URL"
    EMAIL       = "EMAIL"
    FILE_HASH   = "FILE_HASH"
    ATTACHMENT  = "ATTACHMENT"


# ---------------------------------------------------------------------------
# Authentication verdicts
# ---------------------------------------------------------------------------

class AUTH_VERDICTS:
    PASS     = "PASS"
    WARN     = "WARN"
    FAIL     = "FAIL"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Well-known brands for lookalike / typosquat detection (130+ entries)
# ---------------------------------------------------------------------------

WELL_KNOWN_BRANDS: list[str] = [
    # Big Tech
    "google", "microsoft", "apple", "amazon", "meta", "facebook", "instagram",
    "twitter", "x", "linkedin", "youtube", "whatsapp", "telegram", "snapchat",
    "tiktok", "pinterest", "reddit", "discord", "slack", "zoom", "teams",
    "skype", "webex",
    # Cloud / Dev
    "github", "gitlab", "bitbucket", "dropbox", "box", "onedrive", "icloud",
    "googlecloud", "aws", "azure", "digitalocean", "heroku", "cloudflare",
    "atlassian", "jira", "confluence", "notion", "figma", "adobe",
    # E-commerce / Retail
    "ebay", "walmart", "aliexpress", "alibaba", "etsy", "shopify",
    "flipkart", "myntra", "snapdeal", "meesho", "nykaa", "ajio",
    # Payments / Finance (Global)
    "paypal", "stripe", "square", "venmo", "cashapp", "zelle", "wise",
    "revolut", "monzo", "n26", "robinhood", "coinbase", "binance", "kraken",
    # US Banks
    "chase", "wellsfargo", "bankofamerica", "citibank", "usbank", "capitalone",
    "americanexpress", "discover", "barclays", "hsbc", "tdbank", "pnc",
    # Indian Banks & Fintech
    "hdfc", "sbi", "icici", "axis", "kotak", "yesbank", "indusind", "pnb",
    "unionbank", "canarabank", "boi", "iob", "federalbank", "rbl",
    "paytm", "phonepe", "gpay", "googlepay", "bhim", "mobikwik", "freecharge",
    "razorpay", "cashfree", "billdesk",
    # Indian Government / Services
    "uidai", "aadhaar", "incometax", "irctc", "epfo", "digilocker", "umang",
    "cowin", "nsdl", "cibil", "passport",
    # Indian Job / Classifieds
    "naukri", "indeed", "monster", "shine", "timesjobs", "olx", "quikr",
    # Ride / Food / Travel
    "uber", "lyft", "ola", "rapido", "swiggy", "zomato", "airbnb", "booking",
    "expedia", "makemytrip", "yatra", "cleartrip", "goibibo",
    # Streaming / Media
    "netflix", "spotify", "disneyplus", "hotstar", "primevideo", "hulu",
    "applemusic", "soundcloud", "twitch",
    # Security / Antivirus
    "norton", "mcafee", "kaspersky", "avast", "avg", "malwarebytes", "bitdefender",
    # Telecom
    "jio", "airtel", "vodafone", "idea", "bsnl", "att", "verizon", "tmobile",
    # Misc SaaS
    "salesforce", "hubspot", "zendesk", "freshdesk", "intercom", "mailchimp",
    "sendgrid", "twilio", "docusign", "workday", "servicenow",
]

# ---------------------------------------------------------------------------
# URL shortener domains
# ---------------------------------------------------------------------------

URL_SHORTENERS: set[str] = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly",
    "adf.ly", "is.gd", "cli.gs", "yfrog.com", "migre.me", "ff.im",
    "tiny.cc", "url4.eu", "twit.ac", "su.pr", "twurl.nl", "snipurl.com",
    "short.to", "budurl.com", "ping.fm", "post.ly", "just.as", "bkite.com",
    "snipr.com", "fic.kr", "loopt.us", "htxt.it", "dfl.mn", "dlvr.it",
    "shorte.st", "clck.ru", "cutt.ly", "rebrand.ly", "shorturl.at",
    "rb.gy", "tiny.one", "bl.ink", "bc.vc", "mcaf.ee", "qr.net",
    "yourls.org", "v.gd", "x.co", "lnkd.in", "ht.ly", "alturl.com",
    "urlzs.com", "0rz.tw", "2tu.us", "3.ly", "4ms.me", "4sq.com",
    "prettylinkpro.com",
}

# ---------------------------------------------------------------------------
# Suspicious top-level domains
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS: set[str] = {
    ".xyz", ".top", ".click", ".work", ".loan", ".win", ".bid", ".stream",
    ".review", ".country", ".kim", ".science", ".gq", ".ml", ".cf", ".tk",
    ".ga", ".men", ".download", ".racing", ".accountant", ".date", ".faith",
    ".trade", ".webcam", ".party", ".cricket", ".rocks", ".space",
    ".website", ".site", ".online", ".tech", ".store", ".live", ".club",
    ".biz", ".link", ".pw", ".cc",
    ".to", ".ws", ".nu",
}

# ---------------------------------------------------------------------------
# RFC 1918 / Special IP ranges
# ---------------------------------------------------------------------------

RFC1918_RANGES: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),       # Loopback
    ipaddress.IPv4Network("169.254.0.0/16"),    # Link-local
    ipaddress.IPv4Network("100.64.0.0/10"),     # Shared address space (CGNAT)
]

# ---------------------------------------------------------------------------
# Known VPN provider ASNs
# ---------------------------------------------------------------------------

KNOWN_VPN_ASNS: set[int] = {
    # NordVPN
    212238, 204957,
    # ExpressVPN / M247
    9009,
    # Mullvad
    39351,
    # ProtonVPN
    62371,
    # PureVPN / Quadranet
    40676,
    # IPVanish / Highwinds
    36352,
    # Surfshark / Alibaba
    45102,
    # Private Internet Access
    4455,
    # VyprVPN
    29802,
    # Hotspot Shield
    10439,
    # TunnelBear / Bell Canada
    812,
    # AirVPN
    197540,
    # IVPN
    35540,
    # Tor-related
    60729, 205100,
}

# ---------------------------------------------------------------------------
# Known hosting / cloud provider ASNs
# ---------------------------------------------------------------------------

KNOWN_HOSTING_ASNS: set[int] = {
    # Amazon AWS
    16509, 14618,
    # Google Cloud / GCP
    15169,
    # Microsoft Azure
    8075,
    # Cloudflare
    13335,
    # DigitalOcean
    14061,
    # Linode / Akamai
    63949,
    # OVH
    16276,
    # Hetzner
    24940,
    # Vultr / Choopa
    20473,
    # Rackspace
    33070,
    # Leaseweb
    28753,
    # Frantech / BuyVM
    53667,
    # Contabo
    51167,
    # Oracle Cloud
    31898,
    # IBM Cloud
    36351,
    # Alibaba Cloud
    37963,
    # Tencent Cloud
    45090,
    # Hostinger
    47583,
    # GoDaddy
    26496,
    # Namecheap
    22612,
    # Bluehost
    46606,
    # DreamHost
    26347,
    # SiteGround
    35662,
    # A2 Hosting
    55293,
}

# ---------------------------------------------------------------------------
# Urgency / pressure keywords
# ---------------------------------------------------------------------------

URGENCY_KEYWORDS: list[str] = [
    "urgent", "urgently", "immediately", "action required", "action needed",
    "verify now", "confirm now", "respond now", "act now", "respond immediately",
    "suspended", "suspend", "locked", "account locked", "access blocked",
    "expire", "expires", "expiring", "expiration", "will expire",
    "24 hours", "48 hours", "within 24", "within 48", "24-hour", "48-hour",
    "click now", "click here now", "limited time", "time sensitive",
    "time-sensitive", "last chance", "final notice", "final warning",
    "overdue", "past due", "payment due", "invoice due",
    "security alert", "security warning", "unauthorized access",
    "unusual activity", "suspicious activity", "suspicious login",
    "your account will be", "we have detected", "we noticed",
    "failure to", "failure to comply", "non-compliance",
    "do not ignore", "do not delay", "immediate attention",
    "important notice", "important update", "critical update",
]

# ---------------------------------------------------------------------------
# Phishing-specific keywords
# ---------------------------------------------------------------------------

PHISHING_KEYWORDS: list[str] = [
    # Account / credential harvesting
    "confirm your account", "confirm your email", "confirm your identity",
    "update your information", "update your details", "update your account",
    "verify your identity", "verify your account", "verify your email",
    "validate your account", "re-verify", "re-confirm", "reconfirm",
    # Login / access themed
    "click the link below", "click here to", "click the button",
    "sign in to your account", "log in to continue", "reset your password",
    "change your password", "password has been reset",
    "your password will expire", "password expiry", "credentials",
    # Financial lures
    "bank account", "credit card", "debit card", "card number",
    "billing information", "payment information", "invoice attached",
    "refund is ready", "claim your refund", "pending payment",
    "transaction failed", "payment failed", "wire transfer",
    # Prize / reward lures
    "you have been selected", "congratulations you", "you are a winner",
    "claim your prize", "free gift", "won a prize", "lucky winner",
    # Document lures
    "shared a document", "shared a file", "view the document",
    "open the attachment", "download the file", "see the attached",
    # IT / helpdesk impersonation
    "it department", "help desk", "helpdesk", "tech support",
    "your mailbox", "mailbox quota", "inbox full", "storage limit",
    "microsoft account", "google account", "apple id",
    # Generic
    "personal information", "social security", "date of birth",
    "mother maiden name", "security question",
]
