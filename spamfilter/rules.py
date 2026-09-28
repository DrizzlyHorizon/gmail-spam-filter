"""Scores a message: each rule that matches adds its weight from config."""
import re

from .message import domain_of, normalize

# Cyrillic, Hebrew, Arabic, Thai, Japanese kana, CJK, Hangul
NON_LATIN_RE = re.compile(
    "[Ѐ-ӿ֐-׿؀-ۿ฀-๿"
    "぀-ヿ㐀-鿿가-힯]"
)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
MIN_LETTERS_FOR_LANGUAGE = 20

_detector = None


def _english_confidence(text):
    """Returns (confidence that text is English, detected language name)."""
    global _detector
    from lingua import Language, LanguageDetectorBuilder
    if _detector is None:
        _detector = LanguageDetectorBuilder.from_all_languages().build()
    confidence = _detector.compute_language_confidence(text, Language.ENGLISH)
    detected = _detector.detect_language_of(text)
    return confidence, detected.name.title() if detected else "unknown"


def _auth(results, mechanism):
    m = re.search(rf"\b{mechanism}=(\w+)", results)
    return m.group(1) if m else None


def _same_org(domain_a, domain_b):
    """True if the domains share their last two labels (mail.x.com ~ x.com)."""
    return domain_a.split(".")[-2:] == domain_b.split(".")[-2:]


def check_language(msg, w, add):
    text = f"{msg.subject} {msg.text}"
    letters = sum(ch.isalpha() for ch in text)
    if letters < MIN_LETTERS_FOR_LANGUAGE:
        return
    if len(NON_LATIN_RE.findall(text)) / letters > 0.2:
        add(w["non_latin_script"], "non-Latin script")
        return
    confidence, language = _english_confidence(text)
    if confidence < 0.5:
        add(w["non_english"], f"language={language}")


def check_auth(msg, w, add):
    if _auth(msg.auth_results, "dmarc") == "fail":
        add(w["dmarc_fail"], "DMARC fail")
    if _auth(msg.auth_results, "spf") in ("fail", "softfail"):
        add(w["spf_fail"], "SPF fail")
    if _auth(msg.auth_results, "dkim") != "pass":
        add(w["dkim_missing"], "no valid DKIM")


def check_sender(msg, w, rules, add):
    name = msg.from_name.lower()
    domain = msg.from_domain

    spoofed = EMAIL_RE.search(name)
    if spoofed and spoofed.group(0) != msg.from_addr:
        add(w["display_name_spoof"], "display name shows another address")

    squashed_domain = domain.replace("-", "")
    for brand in rules["impersonated_brands"]:
        if re.search(rf"\b{re.escape(brand)}\b", name) and brand.replace(" ", "") not in squashed_domain:
            add(w["brand_impersonation"], f"claims to be {brand}")
            break

    if msg.reply_to and not _same_org(domain_of(msg.reply_to), domain):
        add(w["reply_to_mismatch"], "Reply-To elsewhere")

    if domain.rpartition(".")[2] in rules["suspicious_tlds"]:
        add(w["suspicious_tld"], f".{domain.rpartition('.')[2]} domain")


def check_recipient(msg, w, my_addr, add):
    if normalize(my_addr) not in {normalize(a) for a in msg.recipients}:
        add(w["not_addressed_to_me"], "not addressed to you")


def check_content(msg, w, rules, add):
    haystack = f"{msg.subject} {msg.text}".lower()
    hits = [p for p in rules["spam_phrases"] if p in haystack][:3]
    for phrase in hits:
        add(w["spam_phrase"], f'"{phrase}"')
    if msg.links >= 3 and len(msg.text.split()) < 50:
        add(w["link_heavy"], "mostly links")
    if not msg.subject:
        add(w["empty_subject"], "empty subject")


def score(msg, cfg, my_addr):
    """Returns (total score, list of human-readable reasons)."""
    total, reasons = 0, []

    def add(weight, reason):
        nonlocal total
        if weight:
            total += weight
            reasons.append(f"{reason} +{weight}")

    w, rules = cfg["weights"], cfg["rules"]
    check_language(msg, w, add)
    check_auth(msg, w, add)
    check_sender(msg, w, rules, add)
    check_recipient(msg, w, my_addr, add)
    check_content(msg, w, rules, add)
    return total, reasons
