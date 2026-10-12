"""Rule based prompt-injection detector (OWASP LLM01).

Each rule has a weight. The risk score is the sum of the weights of the rules
that match, capped at 100. A prompt is blocked when the score reaches the
configured threshold. Rules are deliberately simple and readable so you can
explain every decision. They are NOT a complete defence: obfuscated attacks
can slip through, which is why the gateway also scans the model's output.
"""
import re
import unicodedata
from dataclasses import dataclass, field

_ZERO_WIDTH = re.compile(r"[​-‏⁠﻿]")

_FLAGS = re.I | re.S

RULES: list[tuple[str, re.Pattern, int]] = [
    (
        "ignore_instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|your|the)\b.{0,30}\b(instructions?|rules?|prompts?|guidelines?)\b",
            _FLAGS,
        ),
        60,
    ),
    (
        "reveal_system_prompt",
        re.compile(
            r"\b(reveal|show|print|repeat|display|tell me|output|leak)\b.{0,40}\b(system|hidden|initial|original)\b.{0,20}\b(prompt|instructions?|message)\b",
            _FLAGS,
        ),
        60,
    ),
    (
        "transform_hidden_instructions",
        re.compile(
            r"\b(translate|summari[sz]e|rewrite|paraphrase)\b.{0,40}\b(system|hidden|initial|original|your)\b.{0,20}\b(prompt|instructions?|rules)\b",
            _FLAGS,
        ),
        55,
    ),
    (
        "role_override",
        re.compile(
            r"\byou are now\b|\bact as (an? )?(unrestricted|unfiltered|evil|dan)\b|\bpretend (to be|you are)\b",
            _FLAGS,
        ),
        40,
    ),
    (
        "jailbreak_keywords",
        re.compile(r"\b(dan|developer mode|jailbreak(ed)?|do anything now)\b", _FLAGS),
        50,
    ),
    (
        "remove_restrictions",
        re.compile(
            r"\bwithout (any )?(restrictions?|filters?|limitations?|rules?)\b|\bno (restrictions?|filters?|limitations?)\b|\bbypass\b.{0,20}\b(safety|filter|guardrails?|restrictions?)\b",
            _FLAGS,
        ),
        50,
    ),
    (
        "secrets_request",
        re.compile(
            r"\b(api[ _-]?key|password|secret|token|credentials?)\b.{0,30}\b(give|show|reveal|print|tell|send)\b|\b(give|show|reveal|print|tell|send)\b.{0,30}\b(api[ _-]?key|password|secret|token|credentials?)\b",
            _FLAGS,
        ),
        45,
    ),
    (
        "delimiter_injection",
        re.compile(
            r"(<\|?(system|im_start|im_end|end)\|?>|\[/?INST\]|###\s*(system|instruction))",
            _FLAGS,
        ),
        50,
    ),
    (
        "encoded_payload",
        re.compile(
            r"\b(base64|rot13|hex)\b.{0,30}\b(decode|decoded|follow|execute)\b|\b(decode|decoded)\b.{0,30}\b(base64|rot13|hex)\b",
            _FLAGS,
        ),
        35,
    ),
    (
        "exfiltration",
        re.compile(r"\b(send|post|upload|forward)\b.{0,40}\b(to|at)\s+https?://", _FLAGS),
        40,
    ),
]


@dataclass
class Detection:
    score: int = 0
    rules: list[str] = field(default_factory=list)


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def detect(text: str) -> Detection:
    clean = normalize(text)
    score = 0
    hits: list[str] = []
    for name, pattern, weight in RULES:
        if pattern.search(clean):
            hits.append(name)
            score += weight
    return Detection(score=min(score, 100), rules=hits)
