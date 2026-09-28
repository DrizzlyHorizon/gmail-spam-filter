# Gmail Spam Filter

Runs on a Raspberry Pi and cleans junk out of a Gmail inbox, aimed at the
foreign-language spam that follows a data leak.

Every 10 minutes it checks new mail. Anyone in your contacts, or anyone you've
emailed, is never touched. Everything else gets a score:

| Signal | Points |
|---|---|
| Not in English / non-Latin script | 6 |
| DMARC fail / SPF fail / no valid DKIM | 3 / 2 / 1 |
| Display name hides another address, or claims to be a brand it isn't | 3 |
| Suspicious domain ending (.xyz, .top, .ru…) | 2 |
| Scam phrases ("verify your account", "lottery"…) | 2 each, max 3 |
| BCC'd / Reply-To elsewhere / mostly links / empty subject | 1 each |

| Score | Action |
|---|---|
| 3–5 | Labeled **Spam-Review** and archived, so you can look it over |
| 6+ | **Reported as spam** (Gmail learns from this; spam empties itself after 30 days) |
| 9+ | Also **blocked**: a Gmail filter sends future mail from that domain to trash (for Gmail/Outlook/etc. senders it blocks just the address) |

All weights, thresholds, and word lists are in [config.example.toml](config.example.toml).

## 1. Google Cloud setup (once, on your PC)

1. Go to <https://console.cloud.google.com/> and create a project named `gmail-spam-filter`.
2. **APIs & Services → Library**: enable **Gmail API** and **People API**.
3. **Google Auth Platform → Branding** (or "OAuth consent screen"): choose **External**, fill in an app name and your email.
4. **Audience**: add your Gmail address as a test user, then click **Publish app** so the status is **In production**.
   Skipping this means your sign-in expires every 7 days and the filter quietly stops.
5. **Clients → Create client → Desktop app**. Download the JSON and rename it to `credentials.json`.

## 2. Install on the Pi

```bash
sudo apt update && sudo apt install -y git python3-venv
git clone https://github.com/<your-username>/gmail-spam-filter.git ~/gmail-spam-filter
cd ~/gmail-spam-filter
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

From your PC (PowerShell), copy the credentials over:

```powershell
scp credentials.json <pi-user>@<pi-address>:~/gmail-spam-filter/data/
```

## 3. Sign in (once)

The Pi has no browser, so connect with an SSH tunnel and use your PC's browser:

```powershell
ssh -L 8765:localhost:8765 <pi-user>@<pi-address>
```

Then, in that SSH session:

```bash
cd ~/gmail-spam-filter
.venv/bin/python -m spamfilter auth
```

Open the printed URL on your PC. Google will warn that the app isn't verified;
that's expected for your own app. Click **Advanced → Go to gmail-spam-filter**
and allow access.

## 4. Dry run (changes nothing)

```bash
.venv/bin/python -m spamfilter run          # last 14 days
.venv/bin/python -m spamfilter -v run       # also list the mail it would keep
```

Every flagged message is printed with its score and reasons. To adjust anything,
create `data/config.toml` with only the settings you want to change:

```toml
[allowlist]
domains = ["mybank.com", "mycompany.com"]

[thresholds]
spam = 7
```

Run the dry run as often as you like while tuning.

## 5. Go live

Add this to `data/config.toml`:

```toml
dry_run = false
```

Run the filter once by hand. The first live run cleans up the last 14 days:

```bash
.venv/bin/python -m spamfilter run
```

Then schedule it every 10 minutes:

```bash
mkdir -p ~/.config/systemd/user
cp deploy/spamfilter.service deploy/spamfilter.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now spamfilter.timer
sudo loginctl enable-linger $USER      # keep running when you're logged out
```

Watch it work: `journalctl _SYSTEMD_USER_UNIT=spamfilter.service -f`
(Raspberry Pi OS keeps user-service logs in the system journal, so `journalctl --user` shows nothing.)

## Undoing mistakes

- **Spam folder:** open the message and click **Not spam**. On its next run the filter
  notices and always allows that sender from then on (it prints `LEARNED <sender>`).
- **Spam-Review label:** move it back to the inbox. That sender is learned the same way.
- **Blocks:** Gmail **Settings → Filters and Blocked Addresses**.

## Optional: local AI second opinion

A Pi 5 can run a small model with [Ollama](https://ollama.com). The model is
only asked about borderline mail. It adds or subtracts 3 points, so it can push
a message over or under a threshold.

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:3b
```

```toml
# data/config.toml
[ai]
enabled = true
```

## Updating

```bash
cd ~/gmail-spam-filter && git pull && .venv/bin/pip install -r requirements.txt
```

## Tests

```bash
.venv/bin/pip install pytest
.venv/bin/python -m pytest
```
