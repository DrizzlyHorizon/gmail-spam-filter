"""Turns a raw Gmail API message into the fields the rules look at."""
import base64
import email
import re
from dataclasses import dataclass, field
from email import policy
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

URL_RE = re.compile(r"https?://", re.I)
MAX_TEXT = 3000


@dataclass
class Message:
    id: str
    labels: set = field(default_factory=set)
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    recipients: list = field(default_factory=list)  # To + Cc addresses
    subject: str = ""
    auth_results: str = ""
    text: str = ""
    links: int = 0

    @property
    def from_domain(self):
        return domain_of(self.from_addr)


def domain_of(addr):
    return addr.rpartition("@")[2].lower()


def normalize(addr):
    """Lowercase, and for Gmail drop dots and +tags so aliases compare equal."""
    addr = addr.strip().lower()
    local, _, domain = addr.rpartition("@")
    if domain in ("gmail.com", "googlemail.com"):
        local = local.split("+", 1)[0].replace(".", "")
        domain = "gmail.com"
    return f"{local}@{domain}" if local else addr


class _HtmlText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self.links, self._skip = [], 0, 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a" and any(k == "href" for k, _ in attrs):
            self.links += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def _content(part):
    if part is None:
        return ""
    try:
        return part.get_content()
    except (LookupError, UnicodeError, AssertionError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _header(msg, name):
    try:
        return str(msg.get(name, "") or "")
    except Exception:  # malformed header; don't let one bad email stop the run
        return ""


def parse(gmail_msg):
    raw = base64.urlsafe_b64decode(gmail_msg["raw"])
    msg = email.message_from_bytes(raw, policy=policy.default)

    from_name, from_addr = parseaddr(_header(msg, "From"))
    _, reply_to = parseaddr(_header(msg, "Reply-To"))
    recipients = [a for _, a in getaddresses([_header(msg, "To"), _header(msg, "Cc")]) if a]
    auth = next((str(h) for h in msg.get_all("Authentication-Results", [])
                 if "mx.google.com" in str(h)), "")

    plain = _content(msg.get_body(preferencelist=("plain",)))
    html = _content(msg.get_body(preferencelist=("html",)))
    links = 0
    if html:
        parser = _HtmlText()
        try:
            parser.feed(html)
        except Exception:
            pass
        links = parser.links
        if not plain:
            plain = " ".join(parser.parts)
    if not links:
        links = len(URL_RE.findall(plain))

    text = " ".join(plain.split())[:MAX_TEXT]
    return Message(
        id=gmail_msg["id"],
        labels=set(gmail_msg.get("labelIds", [])),
        from_name=from_name.strip(),
        from_addr=from_addr.lower(),
        reply_to=reply_to.lower(),
        recipients=[a.lower() for a in recipients],
        subject=" ".join(_header(msg, "Subject").split()),
        auth_results=auth.lower(),
        text=text,
        links=links,
    )
