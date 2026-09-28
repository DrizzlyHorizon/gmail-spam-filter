"""Tiny JSON state file: where we left off, cached contacts, and senders you rescued."""
import json
import time
from pathlib import Path

CONTACTS_TTL = 24 * 3600


class State:
    def __init__(self, path):
        self.path = Path(path)
        data = json.loads(self.path.read_text()) if self.path.exists() else {}
        self.history_id = data.get("history_id")
        self.contacts = set(data.get("contacts", []))
        self.contacts_refreshed = data.get("contacts_refreshed", 0)
        self.rescued = set(data.get("rescued", []))  # senders you marked "Not spam"

    def contacts_stale(self):
        return time.time() - self.contacts_refreshed > CONTACTS_TTL

    def set_contacts(self, emails):
        self.contacts = set(emails)
        self.contacts_refreshed = time.time()

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "history_id": self.history_id,
            "contacts": sorted(self.contacts),
            "contacts_refreshed": self.contacts_refreshed,
            "rescued": sorted(self.rescued),
        }, indent=1))
        tmp.replace(self.path)
