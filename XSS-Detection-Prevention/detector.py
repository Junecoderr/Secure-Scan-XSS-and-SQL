import re

def detect_xss(user_input):

    patterns = [
        r"<\s*script\b",
        r"\bon\w+\s*=",
        r"javascript\s*:",
        r"<\s*iframe\b",
    ]

    for pattern in patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True

    return False
SQLI_PATTERNS = [
    r"\bOR\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
    r"\bAND\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
    r"\bUNION\b\s+\bSELECT\b",
    r"\bSELECT\b.+\bFROM\b",
    r"\bINSERT\b\s+INTO\b",
    r"\bDROP\b\s+TABLE\b",
    r"\bDELETE\b\s+FROM\b",
    r"\bUPDATE\b\s+\w+\s+SET\b",
    r"--",
    r"/\*.*?\*/",
    r"\bSLEEP\s*\(",
    r"\bWAITFOR\s+DELAY\b"
]


def detect_sqli(user_input):
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True

    return False