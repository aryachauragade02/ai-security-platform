"""Find and hide sensitive data (OWASP LLM02) in prompts and model answers."""
import re
from dataclasses import dataclass, field


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# (label, pattern, optional validator). Order matters: more specific first.
PATTERNS: list[tuple[str, re.Pattern, object]] = [
    (
        "api_key",
        re.compile(
            r"(AIza[0-9A-Za-z_\-]{35}|sk-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}"
            r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"
        ),
        None,
    ),
    ("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), None),
    ("credit_card", re.compile(r"(?<!\d)(?:\d[ -]?){13,16}(?!\d)"), _luhn_ok),
    ("aadhaar", re.compile(r"(?<!\d)[2-9]\d{3}\s?\d{4}\s?\d{4}(?!\d)"), None),
    ("pan", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), None),
    ("phone", re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)"), None),
]


@dataclass
class Redaction:
    text: str
    findings: dict[str, int] = field(default_factory=dict)


def redact(text: str, secrets: tuple[str, ...] = ()) -> Redaction:
    """Replace sensitive values with [REDACTED_<TYPE>] and count what was found.

    `secrets` are exact strings that must never appear (for example a canary or a
    real internal code). They are matched case-insensitively.
    """
    findings: dict[str, int] = {}

    def bump(label: str) -> None:
        findings[label] = findings.get(label, 0) + 1

    for secret in secrets:
        if not secret:
            continue
        pattern = re.compile(re.escape(secret), re.I)
        text, n = pattern.subn("[REDACTED_SECRET]", text)
        if n:
            findings["secret"] = findings.get("secret", 0) + n

    for label, pattern, validator in PATTERNS:

        def repl(match: re.Match, label=label, validator=validator) -> str:
            if validator is not None and not validator(match.group(0)):
                return match.group(0)
            bump(label)
            return f"[REDACTED_{label.upper()}]"

        text = pattern.sub(repl, text)

    return Redaction(text=text, findings=findings)
