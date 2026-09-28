"""Thin wrapper around the Gmail and People APIs."""
import logging
from pathlib import Path

from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

log = logging.getLogger(__name__)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",           # read, label, spam, trash
    "https://www.googleapis.com/auth/gmail.settings.basic",   # create block filters
    "https://www.googleapis.com/auth/contacts.readonly",       # allowlist: contacts
    "https://www.googleapis.com/auth/contacts.other.readonly",  # allowlist: people you've emailed
]
RETRIES = 3


def authorize(data_dir, port):
    """One-time sign-in. Prints a URL to open in a browser (see README for the SSH tunnel)."""
    data_dir = Path(data_dir)
    secrets = data_dir / "credentials.json"
    if not secrets.exists():
        raise SystemExit(f"Missing {secrets}. Download it from Google Cloud Console first.")
    flow = InstalledAppFlow.from_client_secrets_file(str(secrets), SCOPES)
    creds = flow.run_local_server(port=port, open_browser=False)
    (data_dir / "token.json").write_text(creds.to_json())
    print("Authorized. Token saved to", data_dir / "token.json")


def load_credentials(data_dir):
    token = Path(data_dir) / "token.json"
    if not token.exists():
        raise SystemExit("Not authorized yet. Run: python -m spamfilter auth")
    creds = Credentials.from_authorized_user_file(str(token), SCOPES)
    if not creds.valid:
        try:
            creds.refresh(Request())
        except RefreshError as e:
            raise SystemExit(
                f"Google sign-in expired or was revoked ({e}). Run: python -m spamfilter auth\n"
                "If this happens every 7 days, publish the OAuth app to production (see README)."
            )
        token.write_text(creds.to_json())
    return creds


class Gmail:
    def __init__(self, creds):
        self.svc = build("gmail", "v1", credentials=creds, cache_discovery=False)
        self.people = build("people", "v1", credentials=creds, cache_discovery=False)
        self.users = self.svc.users()

    def profile(self):
        return self.users.getProfile(userId="me").execute(num_retries=RETRIES)

    def search_ids(self, query):
        ids = []
        req = self.users.messages().list(userId="me", q=query, maxResults=500)
        while req is not None:
            resp = req.execute(num_retries=RETRIES)
            ids += [m["id"] for m in resp.get("messages", [])]
            req = self.users.messages().list_next(req, resp)
        return ids

    def new_message_ids(self, start_history_id):
        """Messages added since start_history_id -> (ids, latest history id), or None if too old."""
        ids, latest = [], start_history_id
        req = self.users.history().list(userId="me", startHistoryId=start_history_id,
                                        historyTypes=["messageAdded"], maxResults=500)
        try:
            while req is not None:
                resp = req.execute(num_retries=RETRIES)
                for h in resp.get("history", []):
                    ids += [a["message"]["id"] for a in h.get("messagesAdded", [])]
                latest = resp.get("historyId", latest)
                req = self.users.history().list_next(req, resp)
        except HttpError as e:
            if e.resp.status == 404:
                return None
            raise
        return list(dict.fromkeys(ids)), latest

    def get_raw(self, msg_id):
        try:
            return self.users.messages().get(userId="me", id=msg_id, format="raw").execute(num_retries=RETRIES)
        except HttpError as e:
            if e.resp.status == 404:  # deleted since it arrived
                return None
            raise

    def label_id(self, name):
        """Returns the id of a user label, creating it if needed."""
        labels = self.users.labels().list(userId="me").execute(num_retries=RETRIES).get("labels", [])
        for label in labels:
            if label["name"] == name:
                return label["id"]
        return self.users.labels().create(userId="me", body={"name": name}).execute(num_retries=RETRIES)["id"]

    def modify(self, msg_id, add=(), remove=()):
        body = {"addLabelIds": list(add), "removeLabelIds": list(remove)}
        self.users.messages().modify(userId="me", id=msg_id, body=body).execute(num_retries=RETRIES)

    def trash(self, msg_id):
        self.users.messages().trash(userId="me", id=msg_id).execute(num_retries=RETRIES)

    def filter_senders(self):
        resp = self.users.settings().filters().list(userId="me").execute(num_retries=RETRIES)
        return [f.get("criteria", {}).get("from", "").lower() for f in resp.get("filter", [])]

    def block(self, sender):
        """Same as Gmail's own "Block": future mail from sender goes straight to trash."""
        body = {"criteria": {"from": sender}, "action": {"addLabelIds": ["TRASH"], "removeLabelIds": ["INBOX"]}}
        self.users.settings().filters().create(userId="me", body=body).execute(num_retries=RETRIES)

    def contact_emails(self):
        emails = set()
        sources = [
            (self.people.people().connections(), "connections",
             {"resourceName": "people/me", "personFields": "emailAddresses", "pageSize": 1000}),
            (self.people.otherContacts(), "otherContacts",
             {"readMask": "emailAddresses", "pageSize": 1000}),
        ]
        for resource, key, params in sources:
            req = resource.list(**params)
            while req is not None:
                resp = req.execute(num_retries=RETRIES)
                for person in resp.get(key, []):
                    emails.update(e["value"].lower() for e in person.get("emailAddresses", []) if e.get("value"))
                req = resource.list_next(req, resp)
        return emails
