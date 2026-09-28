"""Command line entry point: `python -m spamfilter auth` / `python -m spamfilter run`."""
import argparse
import logging
from collections import Counter
from pathlib import Path

from . import ai, rules
from .config import ROOT, load_config
from .gmail import Gmail, authorize, load_credentials
from .message import domain_of, normalize, parse
from .state import State

log = logging.getLogger("spamfilter")
SKIP_LABELS = {"SENT", "DRAFT", "SPAM", "TRASH", "CHAT"}


def build_allowlist(cfg, gmail, state):
    allow = cfg["allowlist"]
    senders = {normalize(s) for s in allow["senders"]}
    if allow["use_contacts"]:
        if state.contacts_stale():
            state.set_contacts(gmail.contact_emails())
            log.info("Refreshed contacts: %d addresses", len(state.contacts))
        senders |= {normalize(s) for s in state.contacts}
    domains = {d.lower().lstrip("@") for d in allow["domains"]}
    return senders, domains


def is_allowed(addr, senders, domains):
    if normalize(addr) in senders:
        return True
    domain = domain_of(addr)
    return any(domain == d or domain.endswith("." + d) for d in domains)


def decide(score, thresholds):
    if score >= thresholds["spam"]:
        return "spam"
    if score >= thresholds["review"]:
        return "review"
    return "keep"


class Actions:
    """Applies decisions to the mailbox. Created only when not in dry-run mode."""

    def __init__(self, gmail, cfg):
        self.gmail, self.cfg = gmail, cfg
        self.acts = cfg["actions"]
        self.review_label = gmail.label_id(self.acts["review_label"])
        self._filters = None

    def review(self, msg):
        remove = ["INBOX"] if self.acts["archive_review"] else []
        self.gmail.modify(msg.id, add=[self.review_label], remove=remove)

    def spam(self, msg):
        if self.acts["high_action"] == "trash":
            self.gmail.trash(msg.id)
        else:
            self.gmail.modify(msg.id, add=["SPAM"], remove=["INBOX"])

    def block(self, msg):
        """Blocks the whole domain, or just the address for Gmail/Outlook/etc. senders."""
        target = msg.from_domain
        if target in self.cfg["rules"]["freemail_domains"]:
            target = msg.from_addr
        if self._filters is None:
            self._filters = set(self.gmail.filter_senders())
        if target in self._filters:
            return None
        if len(self._filters) >= self.acts["max_filters"]:
            log.warning("Filter limit reached (%d); not blocking %s", self.acts["max_filters"], target)
            return None
        self.gmail.block(target)
        self._filters.add(target)
        return target


def process(msg, cfg, my_addr, actions):
    """Scores one message, logs the verdict, and applies it unless dry-running."""
    score, reasons = rules.score(msg, cfg, my_addr)
    t, ai_cfg = cfg["thresholds"], cfg["ai"]

    if ai_cfg["enabled"] and ai_cfg["min_score"] <= score < t["spam"]:
        verdict = ai.classify(msg, ai_cfg)
        if verdict and verdict[1] >= ai_cfg["min_confidence"]:
            is_spam, _, why = verdict
            delta = ai_cfg["weight"] if is_spam else -ai_cfg["weight"]
            score += delta
            reasons.append(f"AI: {why} {delta:+d}")

    action = decide(score, t)
    if action == "keep":
        log.debug("keep    %2d  %s  %r", score, msg.from_addr, msg.subject[:60])
        return action

    blocked = None
    if actions:
        if action == "review":
            actions.review(msg)
        else:
            actions.spam(msg)
            if score >= t["block"] and cfg["actions"]["create_block_filters"]:
                blocked = actions.block(msg)

    log.info("%-7s %2d  %s  %r  [%s]%s", action, score, msg.from_addr, msg.subject[:60],
             ", ".join(reasons), f"  blocked {blocked}" if blocked else "")
    return action


def run(args):
    cfg = load_config(args.data_dir)
    dry_run = cfg["dry_run"] if args.dry_run is None else args.dry_run
    gmail = Gmail(load_credentials(args.data_dir))
    state = State(args.data_dir / "state.json")
    profile = gmail.profile()
    my_addr = profile["emailAddress"]
    senders, domains = build_allowlist(cfg, gmail, state)

    if args.backfill or state.history_id is None:
        days = args.backfill or cfg["backfill_days"]
        log.info("Scanning mail from the last %d days", days)
        ids = gmail.search_ids(f"newer_than:{days}d -in:sent -in:chats")
        latest = profile["historyId"]
    else:
        result = gmail.new_message_ids(state.history_id)
        if result is None:
            log.warning("Saved position too old; scanning the last day instead")
            ids, latest = gmail.search_ids("newer_than:1d -in:sent -in:chats"), profile["historyId"]
        else:
            ids, latest = result

    actions = None if dry_run else Actions(gmail, cfg)
    counts = Counter()
    for msg_id in ids:
        raw = gmail.get_raw(msg_id)
        if raw is None or SKIP_LABELS & set(raw.get("labelIds", [])):
            continue
        try:
            msg = parse(raw)
            if actions and actions.review_label in msg.labels:
                continue
            if is_allowed(msg.from_addr, senders, domains):
                counts["allowed"] += 1
                continue
            counts[process(msg, cfg, my_addr, actions)] += 1
        except Exception:
            log.exception("Failed on message %s", msg_id)
            counts["errors"] += 1

    if not dry_run:
        state.history_id = latest
    state.save()
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no new mail"
    log.info("%sChecked %d messages: %s", "[DRY RUN] " if dry_run else "", len(ids), summary)


def main():
    parser = argparse.ArgumentParser(prog="spamfilter", description="Gmail spam filter")
    parser.add_argument("--data-dir", type=Path,
                        default=ROOT / "data", help="where credentials, token and state live")
    parser.add_argument("-v", "--verbose", action="store_true", help="also show kept messages")
    sub = parser.add_subparsers(dest="command", required=True)

    auth = sub.add_parser("auth", help="one-time Google sign-in")
    auth.add_argument("--port", type=int, default=8765)

    r = sub.add_parser("run", help="check new mail")
    r.add_argument("--dry-run", action=argparse.BooleanOptionalAction, default=None,
                   help="override dry_run from config")
    r.add_argument("--backfill", type=int, metavar="DAYS", help="rescan the last DAYS days")

    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("googleapiclient").setLevel(logging.WARNING)

    if args.command == "auth":
        authorize(args.data_dir, args.port)
    else:
        run(args)


if __name__ == "__main__":
    main()
