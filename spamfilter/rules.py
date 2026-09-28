"""Scores a message: each rule that matches adds its weight from config."""
import re

from .message import domain_of, normalize

NON_LATIN_RANGES = [
    (0x0370, 0x03FF),  # Greek
    (0x0400, 0x04FF),  # Cyrillic
    (0x0590, 0x05FF),  # Hebrew
    (0x0600, 0x06FF),  # Arabic
    (0x0900, 0x097F),  # Devanagari
    (0x0E00, 0x0E7F),  # Thai
    (0x3040, 0x30FF),  # Japanese kana
    (0x3400, 0x9FFF),  # CJK
    (0xAC00, 0xD7AF),  # Hangul
]
NON_LATIN_RE = re.compile("[" + "".join(f"{chr(a)}-{chr(b)}" for a, b in NON_LATIN_RANGES) + "]")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
MIN_LETTERS_FOR_LANGUAGE = 20
# "Dear Joshua," / "Hi Thomas" / "Hola María": a greeting word, an optional title, then a
# capitalized name. The greeting word is case-insensitive; the name must be capitalized.
GREETING_RE = re.compile(
    r"(?<![A-Za-z])(?i:dear|hi|hello|hey|greetings|good morning|good afternoon|good evening|"
    r"hola|estimado|estimada|bonjour|cher|chère|hallo|liebe|lieber|ciao|gentile|buongiorno|"
    r"olá|caro|cara|beste|hej|ahoj|dzień dobry|witam|szanowny|szanowna)"
    r" +(?:(?i:mr|mrs|ms|miss|dr|sr|sra|herr|frau|mme|m)\.? +)?"
    r"([A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿ'-]+) *[,!:]"
)

_detector = None

# Languages the detector chooses between. Keeping it to common ones stops short
# or odd English text from being matched to rare languages like Yoruba.
DETECT_LANGUAGES = [
    "ENGLISH", "SPANISH", "FRENCH", "GERMAN", "ITALIAN", "PORTUGUESE", "DUTCH",
    "POLISH", "CZECH", "SLOVAK", "SLOVENE", "CROATIAN", "HUNGARIAN", "ROMANIAN",
    "SWEDISH", "DANISH", "BOKMAL", "FINNISH", "TURKISH", "INDONESIAN", "VIETNAMESE",
    "LITHUANIAN", "LATVIAN", "ESTONIAN", "RUSSIAN", "UKRAINIAN", "GREEK", "ARABIC",
    "CHINESE", "JAPANESE", "KOREAN",
]


def _detect_language(text):
    """Returns (detected language name, confidence that the text is English)."""
    global _detector
    from lingua import Language, LanguageDetectorBuilder
    if _detector is None:
        langs = [getattr(Language, name) for name in DETECT_LANGUAGES]
        _detector = LanguageDetectorBuilder.from_languages(*langs).build()
    detected = _detector.detect_language_of(text)
    confidence = _detector.compute_language_confidence(text, Language.ENGLISH)
    return (detected.name.title() if detected else "Unknown"), confidence


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
    if len(NON_LATIN_RE.findall(text)) / letters > 0.3:
        add(w["non_latin_script"], "non-Latin script")
        return
    language, english_confidence = _detect_language(text)
    if language != "English" and english_confidence < 0.5:
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


def check_recipient(msg, w, my_addr, known, add):
    recipients = {normalize(a) for a in msg.recipients}
    if normalize(my_addr) not in recipients:
        add(w["not_addressed_to_me"], "not addressed to you")
        return
    # Sent to you plus people you don't know (and who don't work for the sender):
    # a contact form or list someone else filled in with your address.
    strangers = [a for a in recipients - {normalize(my_addr)}
                 if a not in known and not _same_org(domain_of(a), msg.from_domain)]
    if len(strangers) >= 2 and not msg.mailing_list:
        add(w["shared_with_strangers"], f"also sent to {len(strangers)} strangers")


def _plain_subject(msg):
    """Lowercase subject with curly apostrophes straightened, so "You’re" matches "you're"."""
    return msg.subject.lower().replace("’", "'").replace("‘", "'")


def check_content(msg, w, rules, add):
    haystack = f"{msg.subject} {msg.text}".lower()
    hits = [p for p in rules["spam_phrases"] if p in haystack][:3]
    for phrase in hits:
        add(w["spam_phrase"], f'"{phrase}"')
    if msg.links >= 3 and len(msg.text.split()) < 50:
        add(w["link_heavy"], "mostly links")
    if not msg.subject:
        add(w["empty_subject"], "empty subject")
    subject = _plain_subject(msg)
    if any(p in subject for p in rules["signup_phrases"]):
        add(w["signup_confirmation"], "sign-up confirmation")


def check_greeting(msg, w, rules, my_names, add):
    """Mail greeting someone else by name ("Dear Joshua") means your address was typed into a
    form under a fake name: a hallmark of subscription bombing."""
    if not my_names:
        return
    m = GREETING_RE.search(msg.text[:200])
    if not m:
        return
    name = m.group(1).strip("'-").lower()
    if name not in {n.lower() for n in my_names} and name not in rules["generic_greetings"]:
        add(w["wrong_name"], f'greets "{m.group(1)}", not you')


def is_protected(msg, rules):
    """Security/purchase notices from authenticated, non-free-mail senders: never filter these."""
    subject = _plain_subject(msg)
    return (_auth(msg.auth_results, "dmarc") == "pass"
            and msg.from_domain not in rules["freemail_domains"]
            and any(p in subject for p in rules["protected_phrases"]))


def score(msg, cfg, my_addr, known=frozenset()):
    """Returns (total score, list of human-readable reasons). known: allowlisted addresses."""
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
    check_recipient(msg, w, my_addr, known, add)
    check_content(msg, w, rules, add)
    check_greeting(msg, w, rules, cfg["allowlist"]["names"], add)
    return total, reasons
