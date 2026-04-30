import re

SQLI_PATTERNS = [
    r"(\bor\b|\band\b)\s+\d+\s*=\s*\d+",
    r"'\s*or\s*'1'\s*=\s*'1",
    r"'\s*or\s*1\s*=\s*1",
    r"--",
    r";\s*drop\s+table",
    r"union\s+select",
    r"information_schema",
]

XSS_PATTERNS = [
    r"<\s*script",
    r"onerror\s*=",
    r"onload\s*=",
    r"javascript\s*:",
    r"<\s*img",
]

TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"/etc/passwd",
    r"boot\.ini",
]

COMMON_BRUTE_WORDS = ["admin", "root", "test", "password", "123", "qwerty"]

def detect_attack(payload_text: str, path: str, method: str):
    """
    Priority:
    1) SQL Injection
    2) XSS
    3) Path Traversal
    4) Brute Force / Login Attempt
    5) Unknown
    """
    text = f"{payload_text or ''} {path or ''}".lower()

    # 1) SQLi
    for p in SQLI_PATTERNS:
        if re.search(p, text):
            return ("SQL Injection", 0.90, "Payload contains SQL operators/keywords typical of SQLi.")

    # 2) XSS
    for p in XSS_PATTERNS:
        if re.search(p, text):
            return ("XSS", 0.90, "Payload contains script/event handler patterns typical of XSS.")

    # 3) Traversal
    for p in TRAVERSAL_PATTERNS:
        if re.search(p, text):
            return ("Path Traversal", 0.85, "Payload contains directory traversal / sensitive file access patterns.")

    # 4) Login attempts (possible brute force)
    if method == "POST" and ("/login" in (path or "") or "/admin/login" in (path or "")):
        if any(w in text for w in COMMON_BRUTE_WORDS):
            return ("Brute Force", 0.60, "Possible credential guessing on login endpoint.")
        return ("Login Attempt", 0.40, "Login form submission captured.")

    # 5) Unknown
    return ("Unknown", 0.20, "No known attack signature matched.")
