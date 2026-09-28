import base64

from spamfilter.__main__ import decide, is_allowed
from spamfilter.config import ROOT, load_config
from spamfilter.message import Message, normalize, parse
from spamfilter.rules import score

CFG = load_config(ROOT / "nonexistent")
ME = "me@gmail.com"
GOOD_AUTH = "mx.google.com; dkim=pass header.i=@example.com; spf=pass; dmarc=pass"


def make(**kw):
    defaults = dict(id="1", from_name="Example", from_addr="news@example.com",
                    recipients=[ME], subject="Your weekly update",
                    auth_results=GOOD_AUTH,
                    text="Here is what happened this week in the project. " * 5)
    return Message(**{**defaults, **kw})


def test_clean_english_mail_is_kept():
    total, reasons = score(make(), CFG, ME)
    assert decide(total, CFG["thresholds"]) == "keep", reasons


def test_russian_mail_is_spam():
    msg = make(subject="Специальное предложение",
               text="Здравствуйте! Мы рады предложить вам уникальную возможность заработать.")
    total, reasons = score(msg, CFG, ME)
    assert decide(total, CFG["thresholds"]) == "spam", reasons


def test_spanish_mail_is_spam():
    msg = make(subject="Oferta especial para usted",
               text="Hola, le escribimos porque tenemos una oportunidad increíble para su negocio. "
                    "Responda a este correo para recibir más información sobre nuestros servicios.")
    total, reasons = score(msg, CFG, ME)
    assert decide(total, CFG["thresholds"]) == "spam", reasons


def test_phishing_signals_add_up():
    msg = make(from_name="PayPal Security", from_addr="alert@secure-login.xyz",
               recipients=[], auth_results="mx.google.com; spf=softfail; dmarc=fail",
               subject="Account suspended", text="Verify your account now or it will be closed. " * 3)
    total, reasons = score(msg, CFG, ME)
    assert decide(total, CFG["thresholds"]) == "spam", reasons
    assert total >= CFG["thresholds"]["block"]


def test_real_paypal_not_flagged_as_impersonation():
    _, reasons = score(make(from_name="PayPal", from_addr="service@paypal.com"), CFG, ME)
    assert not any("claims to be" in r for r in reasons)


def test_gmail_alias_counts_as_addressed_to_me():
    _, reasons = score(make(recipients=["M.E+shopping@gmail.com"]), CFG, ME)
    assert not any("not addressed" in r for r in reasons)


def test_allowlist():
    assert normalize("J.Doe+x@Gmail.com") == "jdoe@gmail.com"
    assert is_allowed("j.doe@gmail.com", {"jdoe@gmail.com"}, set())
    assert is_allowed("billing@mail.mybank.com", set(), {"mybank.com"})
    assert not is_allowed("x@notmybank.com", set(), {"mybank.com"})


def test_parse_raw_message():
    raw = (
        "From: \"Bob\" <Bob@Example.com>\r\n"
        "To: me@gmail.com\r\n"
        "Subject: =?utf-8?b?SGVsbG8=?=\r\n"
        "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        "<html><style>p{}</style><p>Hi <a href='https://a.example'>there</a></p></html>"
    ).encode()
    msg = parse({"id": "abc", "labelIds": ["INBOX"],
                 "raw": base64.urlsafe_b64encode(raw).decode()})
    assert msg.from_addr == "bob@example.com"
    assert msg.subject == "Hello"
    assert msg.text == "Hi there"
    assert msg.links == 1
    assert "dmarc=pass" in msg.auth_results


def test_tracking_links_dont_confuse_language():
    from spamfilter.message import clean_text
    junk = "[https://cdn.us1.exponea.com/e/.eJwTUnidrLXzmvj_T-c7unOZV2s5iF_m75C943jIa95BZgfOG0l]"
    text = clean_text(f"{junk} Test your Endgame memory and see how many scenes you remember. {junk} "
                      "Shop the new collectibles before they sell out this weekend.")
    total, reasons = score(make(text=text), CFG, ME)
    assert not any("language" in r for r in reasons), reasons


def test_signup_confirmation_is_spam():
    total, reasons = score(make(subject="Important: confirm your subscription"), CFG, ME)
    assert decide(total, CFG["thresholds"]) == "spam", reasons
    total, reasons = score(make(subject="Welcome to Silent Success Society"), CFG, ME)
    assert decide(total, CFG["thresholds"]) == "spam", reasons


def test_security_notices_are_protected():
    from spamfilter.rules import is_protected
    real = make(from_addr="customer_support@email.ticketmaster.com",
                subject="Your Ticketmaster password has been updated")
    assert is_protected(real, CFG["rules"])
    spoof = make(from_addr="alerts@secure-login.xyz", subject="Your password has been updated",
                 auth_results="mx.google.com; dmarc=fail")
    assert not is_protected(spoof, CFG["rules"])


def test_first_name_allows_mail():
    from spamfilter.__main__ import mentions_name
    assert mentions_name(make(text="Hi Devin, your order shipped today."), ["Devin"])
    assert mentions_name(make(subject="devin, this is what you missed"), ["Devin"])
    assert not mentions_name(make(text="Hi Kevin, welcome aboard."), ["Devin"])
    assert not mentions_name(make(text="Devinity newsletter"), ["Devin"])


class FakeGmail:
    """Stands in for Gmail: one caught message was rescued with "Not spam"."""
    def __init__(self):
        self.removed = []

    def label_id(self, name):
        return f"id-{name}"

    def search_ids(self, query):
        return ["m1"] if "Spam-Caught" in query else []

    def sender(self, msg_id):
        return "Hello@RealShop.com"

    def modify(self, msg_id, add=(), remove=()):
        self.removed += list(remove)


def test_not_spam_teaches_allowlist(tmp_path):
    from spamfilter.__main__ import Actions
    from spamfilter.state import State
    gmail, state = FakeGmail(), State(tmp_path / "state.json")
    Actions(gmail, CFG).learn_from_rescues(state)
    assert state.rescued == {"hello@realshop.com"}
    assert gmail.removed == ["id-Spam-Caught"]
    state.save()
    assert State(tmp_path / "state.json").rescued == {"hello@realshop.com"}
