# 🛡️ Site Inspector — Trust Checker Pro
### Chrome Extension · v3.0.0

> Instantly analyse any webpage for safety signals, phishing risk, SSL health, email spoofing exposure, mixed content, payment form danger, and more — all from one popup.

---

## 📦 Installation (Developer Mode)

1. **Download** the `site-inspector-v3.zip` and unzip it to a folder.
2. Open Chrome and go to `chrome://extensions`.
3. Enable **Developer Mode** (toggle — top-right corner).
4. Click **Load unpacked** and select the `site-inspector-v3/` folder.
5. The 🛡️ icon will appear in your toolbar. Pin it for quick access.

> ⚠️ This extension is not on the Chrome Web Store. It runs entirely locally — no data is sent to any third-party server except the public APIs listed below.

---

## ✨ Features

### 🔍 Overview Tab
Displays an instant verdict (SAFE / CAUTION / DANGER) based on a 0–100 **Trust Score** computed from:

| Signal | Points |
|---|---|
| HTTPS active | +20 |
| No HTTPS | −30 |
| Privacy Policy found | +8 |
| Contact Page found | +5 |
| Terms of Service found | +5 |
| Copyright notice | +4 |
| Cookie consent banner | +3 |
| Social media links | +3 each |
| Suspicious TLD (.xyz, .top, .click…) | −20 |
| Known good TLD (.com, .gov, .edu…) | +5 |

Also shows: domain, TLD, protocol, page title, language, generator, load time, charset.

---

### 🔒 SSL / Cert Tab
Reports HTTPS/HTTP status, protocol type, certificate validity, and domain. Updates expiry info automatically when WHOIS is run.

---

### 📊 Signals Tab
Visual chips for: HTTPS, Privacy Policy, Contact Page, Terms of Service, Copyright, Cookie Consent, and social media links (Facebook, Twitter, LinkedIn, Instagram).

Also reports: external link count, image count, mixed HTTP link count, and suspicious TLD flag.

---

### 🌐 WHOIS Tab
Fetches live domain registration data from **rdap.org** (no API key needed):
- Registration date & domain age
- Expiry date & days until expiry
- Registrar name
- Nameservers
- Domain handle & status flags

---

### ⚡ Advanced Tab
Eight on-demand security checks (click each button to run):

| Check | API / Method | API Key? |
|---|---|---|
| 🛡️ Google Safe Browsing | Google Transparency Report | No |
| 📅 Wayback Machine Age | archive.org CDX API | No |
| 🚫 DNS Blacklist Lookup | Cloudflare DNS-over-HTTPS | No |
| 📧 SPF / DMARC Email Spoofing | Cloudflare DNS-over-HTTPS | No |
| 🔀 Mixed Content Detector | Live DOM scan | No |
| 💳 Payment Form Warning | Live DOM scan | No |
| 🔗 Redirect Chain Tracer | `performance` API | No |
| 🔔 Site Change Alerts | Content hash + `chrome.storage` | No |

#### 🛡️ Google Safe Browsing
Queries the Google Transparency Report for phishing, malware, or unwanted software flags. Falls back to a direct link if CORS blocks the request.

#### 📅 Wayback Machine Age
Uses the Internet Archive CDX API to find the **earliest recorded snapshot** of the domain — a powerful independent signal of site age that bypasses WHOIS privacy protection.

#### 🚫 DNS Blacklist Lookup
Queries A, MX, and TXT records via Cloudflare's DNS-over-HTTPS. Checks resolved IPs against known suspicious ASN prefixes.

#### 📧 SPF / DMARC Check
Looks up `TXT` records on the domain and `_dmarc.<domain>` to check:
- **SPF**: Prevents spammers from faking your domain's "From" address
- **DMARC**: Enforces what happens when SPF/DKIM fails (`none` / `quarantine` / `reject`)
- Rates spoofing risk as **LOW / MEDIUM / HIGH**

#### 🔀 Mixed Content Detector
Injects a DOM scan into the active tab and reports any `http://` images, scripts, stylesheets, or iframes loaded on an `https://` page — a common sign of a poorly maintained or compromised site.

#### 💳 Payment Form Warning
Scans for card number inputs, CVV/CVC fields, checkout form actions, and Stripe/PayPal integrations. Issues a **HIGH RISK** warning if a payment form is found on an HTTP (unencrypted) page.

#### 🔗 Redirect Chain Tracer
Uses the browser's `performance.getEntriesByType('navigation')` API to count redirect hops and measure redirect time. Multiple redirects can indicate link hijacking or affiliate fraud.

#### 🔔 Site Change Alerts
Computes a hash of the first 5,000 characters of the page's visible text. On first visit the baseline is saved to `chrome.storage.local`. On subsequent visits the hash is compared — any change triggers a **⚠️ PAGE CHANGED** warning with a word-count delta.

---

### ⚙️ Settings Tab

Fully customisable behaviour, persisted across sessions via `chrome.storage.local`.

#### Trust Score Thresholds
Drag the sliders to change when a site is considered SAFE vs CAUTION vs DANGER:

| Slider | Default | Range |
|---|---|---|
| ✅ Safe threshold | 70 | 50 – 95 |
| ⚠️ Caution threshold | 45 | 10 – (safe − 1) |

A live **preview band** updates as you drag so you can see the exact ranges before saving.

#### Auto-Scan Toggles
| Toggle | Effect |
|---|---|
| Auto-run WHOIS on open | Triggers domain age lookup every time the popup opens |
| Auto-scan Mixed Content | Automatically checks for insecure resources |
| Auto-scan Payment Forms | Warns immediately if a checkout is detected |

#### Display Options
| Toggle | Effect |
|---|---|
| Show Score Badge | Hides/shows the `XX/100` badge in the header |
| Compact Mode | Reduces card padding for a denser layout |

Click **💾 SAVE SETTINGS** to persist. Changes to thresholds take effect on the next popup open (or after a manual refresh).

---

## 🏗️ File Structure

```
site-inspector-v3/
├── manifest.json      — Extension config (MV3), permissions, icons
├── popup.html         — Full UI: tabs, cards, settings panel, styles
├── popup.js           — All logic: scoring, rendering, API calls, settings
├── content.js         — Injected into pages (reads DOM metadata)
├── background.js      — Service worker (minimal, MV3 required)
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── README.md          — This file
```

---

## 🔐 Permissions

| Permission | Why it's needed |
|---|---|
| `activeTab` | Read the URL and inject scripts into the current tab |
| `scripting` | Execute DOM-scanning scripts for signals, mixed content, payment forms |
| `storage` | Save settings and site-change baselines locally |
| `host_permissions: <all_urls>` | Allow inspection on any website |

> No data is ever sent to Anthropic, the extension developer, or any analytics service. All API calls go directly to public services (archive.org, rdap.org, Cloudflare DNS).

---

## 🧠 Trust Score Formula

```
Base score: 50

+20  HTTPS active
−30  HTTP (no encryption)
+8   Privacy Policy link found
+5   Contact page link found
+5   Terms of Service link found
+4   Copyright notice in body text
+3   Cookie consent banner found
+3   per social media link (max ~4 links = +12)
+5   Known good TLD (.com, .gov, .edu, .io…)
−20  Suspicious TLD (.xyz, .top, .click, .tk…)
−5   More than 5 plain HTTP outbound links

Final score clamped to 0–100.
```

Default verdicts (customisable in Settings):
- **70–100** → ✅ LIKELY LEGITIMATE
- **45–69** → ⚠️ PROCEED WITH CAUTION
- **0–44**  → 🚨 HIGH RISK — POSSIBLY FAKE

---

## 🌐 External APIs Used

| Service | Endpoint | Data Fetched |
|---|---|---|
| RDAP | `https://rdap.org/domain/<domain>` | Registration dates, registrar, nameservers |
| Wayback CDX | `https://web.archive.org/cdx/…` | Earliest archived snapshot |
| Wayback Available | `https://archive.org/wayback/available?url=…` | Most recent snapshot |
| Google Transparency | `https://transparencyreport.google.com/…` | Safe Browsing status |
| Cloudflare DoH | `https://cloudflare-dns.com/dns-query` | DNS records (A, MX, TXT) |

All APIs are **free**, **public**, and **require no API key**.

---

## 🛠️ Development Notes

- Built with **Manifest V3** (required for new Chrome extensions).
- No build step, no npm, no dependencies — pure HTML/CSS/JS.
- Fonts loaded from Google Fonts CDN (`Space Mono`, `Syne`).
- Service worker (`background.js`) is minimal — MV3 requires it to exist.
- Settings are stored under the key `siteinspector_settings` in `chrome.storage.local`.
- Site change baselines are stored under `sitechange_<base64-url-slice>`.

---

## 📋 Changelog

### v3.0.0
- ✅ Added **Advanced Tab** with 8 new security checks
- ✅ Added **Settings Tab** with configurable trust score thresholds
- ✅ Added auto-scan toggles (WHOIS, mixed content, payment forms)
- ✅ Added display options (compact mode, score badge visibility)
- ✅ Settings persisted via `chrome.storage.local`
- ✅ Threshold changes dynamically re-render verdict on popup open

### v2.0.0
- ✅ Overview, SSL, Signals, WHOIS tabs
- ✅ Trust score engine
- ✅ RDAP WHOIS lookup

### v1.0.0
- ✅ Basic safety popup (SAFE / CAUTION / DANGER)

---

## ⚖️ Disclaimer

This extension provides heuristic analysis only. A **SAFE** verdict does not guarantee a site is trustworthy. Always exercise caution when entering personal or financial information online. The tool is provided as-is with no warranty.
