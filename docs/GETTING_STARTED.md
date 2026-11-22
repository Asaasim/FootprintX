# FootprintX — Getting Started

FootprintX looks at a company's website or network from the outside and lists everything it can find: subdomains, websites, open ports, the software they run, and possible security problems. You give it a target, answer three questions, and it produces a report you can open in your web browser.

> **Only scan things you have written permission to test.** Scanning other people's systems without permission is illegal in most countries.

---

## 1. Install (once)

You need Kali Linux and an internet connection. Installing takes about 5–10 minutes.

1. Download FootprintX: on the GitHub page, click **Code → Download ZIP**, then extract the ZIP into your home folder (right-click → *Extract Here*).
2. Open **Terminal** (the black icon in the top bar).
3. Go into the FootprintX folder and run the installer. If the folder is called `FootprintX-main`, type:

   ```
   cd ~/FootprintX-main
   bash install.sh
   ```

4. When it asks for your password, type your Kali password and press Enter (nothing appears on screen while you type — that's normal).

At the end you'll see **"FootprintX is installed."** and a checklist. Lines marked `[-]` are optional extras; FootprintX still works without them.

---

## 2. Run a scan

1. Open a **new** Terminal window and type:

   ```
   footprintx
   ```

   (Or open the Kali applications menu and click **FootprintX**.)

2. Answer the three questions:

   | Question | What to type |
   | --- | --- |
   | **What do you want to scan?** | A website address like `example.com`, a link like `https://shop.example.com`, an IP address like `203.0.113.10`, or a network range like `192.168.1.0/24`. |
   | **What kind of scan?** | `1` for a **full scan** (finds the most). `2` for a **passive scan** — it only looks at public information and never contacts the target directly. |
   | **Do you have written permission?** | `y` if you do. If you type `n`, nothing is scanned. |

3. Wait. You'll see each step tick off as it finishes. A small website takes a few minutes; a large company can take an hour. To stop early, press **Ctrl + C** — everything found so far is kept.

4. When it finishes, it asks **"Open the report in your web browser now?"** — press Enter.

---

## 3. Read the report

The report has four parts:

- **Summary cards** — how many hosts, websites and open ports were found, and how many issues.
- **Things worth looking at** — possible security problems, most serious first:

  | Label | Meaning |
  | --- | --- |
  | **HIGH** | Likely serious — look at this first (e.g. a database open to the internet, an exposed `.git` folder or password file). |
  | **MEDIUM** | Worth fixing (e.g. directory listing, a backup file anyone can download). |
  | **LOW** | Minor weaknesses (e.g. no HTTPS, an invalid certificate, missing email protection). |
  | **INFO** | Good to know, usually not a problem on its own. |

  These are **leads to check**, not confirmed vulnerabilities.

- **Attack surface** — one card per host with its IP addresses, websites, open ports and technologies.
- **What ran / All findings** — the full details, for reference.

All results are saved in the **FootprintX-results** folder in your home folder — one folder per target, one sub-folder per scan. The report is `reports/report.html` inside it.

To see your previous scans and where their reports are:

```
footprintx history
```

---

## 4. Optional: add a Shodan key

[Shodan](https://www.shodan.io) adds extra information about servers. It is optional.

1. Create a free account at <https://account.shodan.io> and copy your **API key**.
2. In Terminal, type `mousepad ~/.config/footprintx/.env`
3. Paste the key after `SHODAN_API_KEY=` so the line looks like `SHODAN_API_KEY=abc123...`, then save and close.

---

## 5. If something goes wrong

| Problem | What to do |
| --- | --- |
| `footprintx: command not found` | Close Terminal and open a new one. If it still fails, type `~/.local/bin/footprintx` instead. |
| You want to check what's installed | Type `footprintx doctor`. Everything marked `[+]` is working. |
| The scan seems stuck | Big targets take time — the line at the bottom shows what it's doing. Ctrl + C stops it and keeps what was found. |
| "Not understood" when typing a target | Type just the address, e.g. `example.com` — not `www` with spaces, not an email address. |

**Updating:** download the new version of FootprintX the same way and run `bash install.sh` again. Your settings and old results are kept.
