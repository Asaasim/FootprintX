# FootprintX — Getting Started

FootprintX looks at a company's websites and network from the outside and lists everything it can find: subdomains, websites, open ports, the software they run, and possible security problems. You give it a target, answer three questions, and it produces a report you can open in your web browser.

> **Only scan things you have written permission to test.** Scanning other people's systems without permission is illegal in most countries.

**You need:** a computer running **Kali Linux** or **Ubuntu 24.04 or newer** (Debian 12+ and Linux Mint 22+ work too), an internet connection, and your computer password.

**Tip — copying commands:** the grey boxes below contain commands. Select the text, copy it, then paste it into the Terminal with **Ctrl + Shift + V** (plain Ctrl + V does not work in the Terminal). Press **Enter** to run it.

---

## 1. Install (once)

1. Open **Terminal**. On Kali: the black icon in the top bar. On Ubuntu: press **Ctrl + Alt + T**, or search for "Terminal" in the applications menu.
2. Paste this whole block and press **Enter**:

   ```bash
   sudo apt install -y git
   cd ~
   git clone https://github.com/Asaasim/FootprintX.git
   cd FootprintX
   bash install.sh
   ```

3. When it asks for your password, type the password you use to log in to the computer and press **Enter**. Nothing appears on screen while you type — that's normal.
4. Wait. The installer finds out whether you're on Kali or Ubuntu and downloads the right scanning tools, which takes about **10–20 minutes** depending on your internet speed.

When it's done you'll see **"FootprintX is installed."** above a checklist. Lines marked `[+]` are working. Lines marked `[-]` are optional extras (for example the Shodan key from step 4) — FootprintX works without them.

**On Ubuntu**, the installer also prints lines such as `installed subfinder v2.17.0 (checksum verified)` — these tools aren't in Ubuntu's own app store, so it downloads them from their official websites. Everything works the same as on Kali, with two small differences: port scans are a little slower (Ubuntu doesn't allow the fast kind without `sudo`), and the optional Amass tool isn't installed. If the installer says **"FootprintX needs Python 3.11 or newer"**, your Ubuntu is too old (22.04 or earlier) — upgrade to 24.04, or ask a technical person to set it up with Docker (see the README).

### Alternative: download a ZIP

If you prefer not to use `git`: go to <https://github.com/Asaasim/FootprintX>, click the green **Code** button, then **Download ZIP**. Firefox saves it in your **Downloads** folder. Then paste this into the Terminal:

```bash
cd ~
unzip ~/Downloads/FootprintX-main.zip
cd FootprintX-main
bash install.sh
```

---

## 2. Run a scan

1. **Open a new Terminal window** (close the one you installed with) and type:

   ```bash
   footprintx
   ```

   Or open the applications menu (on Ubuntu: the **Show Apps** grid at the bottom left), search for **FootprintX** and click it.

2. Answer the three questions:

   | Question | What to type |
   | --- | --- |
   | **1. What do you want to scan?** | A website address like `example.com`, a link like `https://shop.example.com`, an IP address like `203.0.113.10`, or a network range like `192.168.1.0/24`. Several targets can be separated with spaces. You can also type the path of a text file with one target per line, e.g. `~/targets.txt`. |
   | **2. What kind of scan?** | `1` for a **full scan** — finds the most. `2` for a **passive scan** — only looks at public information and never contacts the target's own servers. If you're unsure whether you may scan actively, start with `2`. |
   | **3. Do you have written permission to test these targets?** | `y` if you do. If you type `n` (or just press Enter), nothing is scanned. |

3. Wait. Each step gets a ✔ when it finishes, and the line at the bottom shows what is running. A small website takes a few minutes; a large company can take an hour. To stop early, press **Ctrl + C** — everything found so far is kept and a report is still written.

4. At the end you'll see a short summary and the most important issues. It then asks **"Open the report in your web browser now?"** — press **Enter**.

---

## 3. Read the report

The report has these parts:

- **Summary cards** — how many hosts, websites and open ports were found, and how many issues.
- **New since the last scan** — only when you've scanned the same target before (with the same kind of scan): anything that appeared since — a new subdomain, a newly opened port, a new issue — is listed here and marked **NEW**.
- **Things worth looking at** — possible security problems, most serious first:

  | Label | Meaning |
  | --- | --- |
  | **HIGH** | Likely serious — look at this first (e.g. a database open to the internet, an exposed `.git` folder or password file). |
  | **MEDIUM** | Worth fixing (e.g. a folder that lists its files, a backup file anyone can download). |
  | **LOW** | Minor weaknesses (e.g. no HTTPS, an invalid certificate, missing email protection). |
  | **INFO** | Good to know, usually not a problem on its own. |

  These are **leads to check**, not confirmed vulnerabilities.

- **Attack surface** — one card per host with its IP addresses, websites, open ports and technologies.
- **What ran** — each step and whether it succeeded, was skipped (and why), or failed.
- **All findings** — the complete lists, for reference (click a section to open it).

### Where everything is saved

Everything goes into the **FootprintX-results** folder in your home folder: one folder per target, and inside it one folder per scan, named by date and time (for example `FootprintX-results/example.com/scan_20261123_141502`). Inside a scan folder:

| File | What it is |
| --- | --- |
| `reports/report.html` | The report — double-click to open it in the browser |
| `reports/findings.csv` | Every finding as a spreadsheet (opens in LibreOffice Calc) |
| `reports/report.txt` | The report as plain text |
| `subdomains.txt`, `open_ports.json`, … | The raw lists, one file per kind of finding |

To list your previous scans and where their reports are:

```bash
footprintx history
```

---

## 4. Optional: add a Shodan key

[Shodan](https://www.shodan.io) adds extra information about servers (what's running on them, known vulnerabilities). It is optional.

1. Create a free account at <https://account.shodan.io> and copy your **API key**.
2. Open the settings file in a text editor:

   ```bash
   mousepad ~/.config/footprintx/.env
   ```

   On Ubuntu use `gnome-text-editor ~/.config/footprintx/.env` instead (or `nano ~/.config/footprintx/.env` — save with **Ctrl + O**, Enter, and quit with **Ctrl + X**).

3. Paste the key right after `SHODAN_API_KEY=` so the line looks like `SHODAN_API_KEY=abc123...` (no spaces), then **save and close** the editor.
4. Check it worked: `footprintx doctor` should now show `[+] Shodan API  Configured`.

Keep this file private — don't share it or put it online.

---

## 5. If something goes wrong

| Problem | What to do |
| --- | --- |
| `footprintx: command not found` | Close the Terminal and open a new one. If it still fails, type `~/.local/bin/footprintx` instead. |
| You want to check what's installed | Type `footprintx doctor`. Everything marked `[+]` is working; `[-]` lines say what to do. |
| The report didn't open | Open the **Files** app → **Home** → **FootprintX-results** → your target → the newest scan folder → `reports` → double-click `report.html`. |
| "was not understood" when typing a target | Type just the address, e.g. `example.com` or `https://example.com` — not an email address, and no spaces inside it. |
| A step says *skipped* | Usually it doesn't apply to that target, or it needs the optional Shodan key. The reason is shown next to it. |
| The scan seems stuck | Large targets take time; the line at the bottom shows what's running. **Ctrl + C** stops it and keeps what was found. |
| `git: command not found` during install | Install git first with `sudo apt install -y git`, then run the install block again. |
| "This installer supports Kali Linux and Ubuntu/Debian" | Your system isn't one of those. FootprintX can still run with Docker — see the README. |
| "could not install …" lines on Ubuntu | That one tool couldn't be downloaded (often a network hiccup). Run `bash install.sh` again later; FootprintX works without it meanwhile. |

---

## Updating

```bash
cd ~/FootprintX
git pull
bash install.sh
```

(If you installed from a ZIP: download the new ZIP, extract it as before and run `bash install.sh` in the new folder.) Your settings, Shodan key and previous results are kept.

## Uninstalling

```bash
pipx uninstall footprintx
rm ~/.local/share/applications/footprintx.desktop
```

On Ubuntu also remove the downloaded tools:

```bash
pipx uninstall theHarvester
rm -f ~/.local/bin/{subfinder,httpx-toolkit,naabu,findomain,assetfinder}
```

This removes the program and its menu entry. Your results (`~/FootprintX-results`) and settings (`~/.config/footprintx`) stay until you delete those folders yourself.
