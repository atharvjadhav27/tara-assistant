"""Scope guard: the assistant never helps with active exploitation or autonomous acceptance."""
import re

EXPLOIT_PATTERNS = [
    r"\b(write|create|build|develop|generate|craft|give me|make)\b.{0,40}\b(exploit|payload|shellcode|malware|ransomware|rootkit|botnet)\b",
    r"\bexploit\b.{0,30}\b(for|against|this|the)\b.{0,40}\b(ecu|vulnerabilit|tcu|vehicle|car|firmware|cve)",
    r"\b(hack|attack|break into|take over|compromise)\b.{0,30}\b(a |the |my |this )?(real |live |actual )?(car|vehicle|ecu|tcu|fleet)",
    r"\b(bypass|crack|brute[- ]?force)\b.{0,40}\b(security access|seed[- ]?key|authentication|immobili[sz]er|secure boot)",
    r"\b(weaponi[sz]e|proof[- ]of[- ]concept exploit|poc exploit)\b",
]
AUTONOMOUS_PATTERNS = [
    r"\b(auto(matically)?|autonomously)\b.{0,30}\b(approve|accept|sign[- ]?off|release)\b",
    r"\b(accept|approve|sign[- ]?off)\b.{0,30}\b(without|no)\b.{0,20}\b(review|engineer|human)\b",
    r"\bskip\b.{0,20}\b(review|approval)\b",
]


def check_scope(text: str) -> dict:
    t = text.lower()
    for p in EXPLOIT_PATTERNS:
        if re.search(p, t):
            return {"allowed": False, "reason": "active_exploitation",
                    "message": "This request is out of scope: the TARA Assistant does not write exploits or support active exploitation. "
                               "I can instead suggest threat scenarios, risk ratings and mitigations for the affected interface."}
    for p in AUTONOMOUS_PATTERNS:
        if re.search(p, t):
            return {"allowed": False, "reason": "autonomous_acceptance",
                    "message": "This request is out of scope: AI output is advisory only. An authorised engineer must review and approve each asset, threat, rating and mitigation."}
    return {"allowed": True, "reason": None, "message": ""}
