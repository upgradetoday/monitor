#!/usr/bin/env python3
"""upgradetoday — latest WordPress & Drupal versions, plus the critical fixes each release addresses.

Two ways to run:

    # 1. Build a static page (what the hourly GitHub Action does)
    WORDFENCE_API_KEY="your-key" python3 upgradetoday.py --build site/index.html

    # 2. Run a local preview server at http://localhost:8000
    WORDFENCE_API_KEY="your-key" python3 upgradetoday.py

Data sources:
    Versions        endoflife.date (open API)
    WordPress vulns Wordfence Intelligence v3 (free API key), cached 6 hours
    Drupal vulns    drupal.org core security advisories RSS (open)
"""
import html
import json
import os
import re
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

# --- Site attribution (edit these) ---
AUTHOR_NAME = "Ben"
TIP_JAR_URL = ""  # e.g. "https://ko-fi.com/yourname" — the tip link is hidden while empty
SOURCE_URL = "https://upgradetoday.github.io/monitor/"

# --- Settings ---
PORT = int(os.environ.get("PORT", 8000))
PAGE_REFRESH_SECONDS = 900
VULN_CACHE_SECONDS = 6 * 3600
WORDFENCE_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
WORDFENCE_KEY = os.environ.get("WORDFENCE_API_KEY", "")
CORE_CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".wordpress_core_vulns.json")
DRUPAL_RSS_URL = "https://www.drupal.org/security/rss.xml"
DRUPAL_CRITICAL_LEVELS = ("Highly critical", "Critical")
USER_AGENT = "upgradetoday/1.0 (+https://upgradetoday.io)"

PRODUCTS = [
    ("wordpress", "WordPress", "https://wordpress.org/download/"),
    ("drupal", "Drupal", "https://www.drupal.org/project/drupal/releases"),
]


# ---------- fetching ----------

def fetch(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_json(url, headers=None, timeout=15):
    return json.loads(fetch(url, headers, timeout))


def latest_for(slug):
    """Return (version, date). Tries endoflife.date API v1, falls back to v0."""
    try:
        res = fetch_json(f"https://endoflife.date/api/v1/products/{slug}/releases/latest")["result"]
        return res["latest"]["name"], res["latest"].get("date", "")
    except Exception:
        cycles = fetch_json(f"https://endoflife.date/api/{slug}.json")
        return cycles[0]["latest"], cycles[0].get("latestReleaseDate", "")


# ---------- WordPress (Wordfence) ----------

def _read_core_cache():
    try:
        with open(CORE_CACHE_FILE) as f:
            return json.load(f)  # {"fetched": epoch, "records": [...]}
    except (OSError, ValueError):
        return None


def wordpress_core_vulns():
    """WordPress core records from the Wordfence feed.

    The full feed is large, so only core records are kept and saved to disk.
    The saved copy is reused for 6 hours, and is also the fallback if a refresh fails.
    """
    cache = _read_core_cache()
    if cache and time.time() - cache.get("fetched", 0) < VULN_CACHE_SECONDS:
        return cache["records"]

    try:
        if not WORDFENCE_KEY:
            raise RuntimeError("WORDFENCE_API_KEY is not set")
        feed = fetch_json(WORDFENCE_URL, {"Authorization": f"Bearer {WORDFENCE_KEY}"}, timeout=180)
    except Exception:
        if cache:
            return cache["records"]
        raise

    records = feed.values() if isinstance(feed, dict) else feed
    core = [
        r for r in records
        if any(s.get("type") == "core" or s.get("slug") == "wordpress" for s in r.get("software", []))
    ]
    with open(CORE_CACHE_FILE, "w") as f:
        json.dump({"fetched": time.time(), "records": core}, f)
    return core


def short_title(title):
    """'WordPress Core 4.3.0 - 7.1.4 - Privilege Escalation' -> 'Privilege Escalation'"""
    ver = r"[<>=]*\s*\d+(?:\.\d+)*"
    return re.sub(rf"^WordPress(?: Core)?\s+{ver}(?:\s*-\s*{ver})?\s+-\s+", "", title).strip()


def wordpress_critical_fixes_in(version, core_records):
    """Critical-rated core vulnerabilities whose patched versions include `version`."""
    hits = []
    for r in core_records:
        cvss = r.get("cvss") or {}
        score = cvss.get("score") or 0
        if cvss.get("rating") != "Critical" and score < 9.0:
            continue
        patched = {v for s in r.get("software", []) for v in s.get("patched_versions", [])}
        if version in patched:
            hits.append({
                "title": short_title(r.get("title", "Untitled")),
                "score": score,
                "cve": r.get("cve") or "",
                "link": (r.get("references") or ["https://www.wordfence.com/threat-intel/"])[0],
            })
    return sorted(hits, key=lambda h: -float(h["score"]))


# ---------- Drupal (drupal.org advisories) ----------

def drupal_critical_fixes_in(version, rss_text=None):
    """Critical / Highly critical core advisories whose text names `version` as the fix."""
    if rss_text is None:
        rss_text = fetch(DRUPAL_RSS_URL)

    # Match "11.3.2" or "11.3.2." (end of sentence) but not "11.3.21" or "111.3.2"
    version_re = re.compile(rf"(?<![\d.]){re.escape(version)}(?!\.?\d)")
    hits = []
    for item in ET.fromstring(rss_text).iter("item"):
        title = (item.findtext("title") or "").strip()
        body = item.findtext("description") or ""
        # Title format: "Drupal core - Critical - Access bypass - SA-CORE-2026-001"
        parts = [p.strip() for p in title.split(" - ")]
        level = next((p for p in parts if p in DRUPAL_CRITICAL_LEVELS), None)
        if not level or not version_re.search(body):
            continue
        i = parts.index(level)
        kind = parts[i + 1] if i + 1 < len(parts) else title
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", body)))
        hits.append({
            "title": kind,
            "score": level,
            "cve": ", ".join(cves),
            "link": (item.findtext("link") or DRUPAL_RSS_URL).strip(),
        })
    return sorted(hits, key=lambda h: h["score"] != "Highly critical")


# ---------- assembling ----------

def get_data():
    data = []
    for slug, name, link in PRODUCTS:
        item = {"slug": slug, "name": name, "link": link, "version": None, "date": "", "vulns": None}
        try:
            item["version"], item["date"] = latest_for(slug)
        except Exception as e:
            print(f"[{slug}] version lookup failed: {e}", file=sys.stderr)
        if item["version"]:
            try:
                if slug == "wordpress":
                    item["vulns"] = wordpress_critical_fixes_in(item["version"], wordpress_core_vulns())
                elif slug == "drupal":
                    item["vulns"] = drupal_critical_fixes_in(item["version"])
            except Exception as e:
                print(f"[{slug}] vulnerability lookup failed: {e}", file=sys.stderr)
                item["vuln_error"] = "Vulnerability data unavailable"
        data.append(item)
    return data


# ---------- rendering ----------

def vuln_section(item):
    if item.get("vuln_error"):
        return f'<div class="vulns"><p class="none">{html.escape(item["vuln_error"])}</p></div>'
    if item["vulns"] is None:
        return ""
    if not item["vulns"]:
        return '<div class="vulns"><p class="none">No critical fixes in this release</p></div>'
    rows = ""
    for v in item["vulns"]:
        numeric = isinstance(v["score"], (int, float))
        cve = f' <span class="cve">{html.escape(v["cve"])}</span>' if v["cve"] else ""
        rows += f'''
          <li><a href="{html.escape(v["link"])}" target="_blank" rel="noopener">
            <span class="score{"" if numeric else " level"}">{html.escape(str(v["score"]))}</span>
            <span class="vtitle">{html.escape(v["title"])}{cve}</span>
          </a></li>'''
    n = len(item["vulns"])
    return f'''<div class="vulns">
        <p class="vhead">{n} critical fix{"es" if n != 1 else ""}</p>
        <ul>{rows}</ul>
      </div>'''


def card(item):
    name = html.escape(item["name"])
    if item["version"]:
        version = html.escape(item["version"])
        meta = f"Released {html.escape(item['date'])}" if item["date"] else "&nbsp;"
        cls = ""
    else:
        version, meta, cls = "—", "Couldn't reach the data source", " error"
    return f"""
      <section class="card{cls}">
        <a class="top" href="{html.escape(item['link'])}" target="_blank" rel="noopener">
          <span class="label">{name}</span>
          <span class="version">{version}</span>
          <span class="meta">{meta}</span>
        </a>
        {vuln_section(item)}
      </section>"""


def render(data, checked_at):
    cards = "".join(card(i) for i in data)
    iso = checked_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    fallback = checked_at.strftime("%b %d, %Y · %H:%M UTC")
    tip = (f' · <a class="tip" href="{html.escape(TIP_JAR_URL)}" target="_blank" rel="noopener">☕ Tip jar</a>'
           if TIP_JAR_URL else "")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="{PAGE_REFRESH_SECONDS}">
<meta name="description" content="Latest WordPress and Drupal releases, and the critical vulnerabilities each one fixes.">
<title>Upgrade Today — latest WordPress &amp; Drupal releases</title>
<style>
  :root {{
    --bg: #0f1115; --surface: #171a21; --border: #262a33;
    --text: #e8eaed; --muted: #8b919c; --accent: #4ade80;
    --critical: #f87171; --critical-bg: rgba(248,113,113,.10);
  }}
  @media (prefers-color-scheme: light) {{
    :root {{ --bg: #f6f7f9; --surface: #fff; --border: #e3e5e9;
            --text: #14161a; --muted: #6b7280; --accent: #15803d;
            --critical: #b91c1c; --critical-bg: rgba(185,28,28,.07); }}
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html, body {{ height: 100%; }}
  body {{
    width: 100%; min-height: 100vh;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 2.5rem; padding: 2rem;
    background: var(--bg); color: var(--text);
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  }}
  h1 {{ font-size: .8rem; font-weight: 600; letter-spacing: .18em; text-transform: uppercase; color: var(--muted); }}
  .grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1.5rem; width: 100%; max-width: 820px; align-items: start;
  }}
  .card {{
    border-radius: 16px; background: var(--surface); border: 1px solid var(--border);
    overflow: hidden; transition: border-color .15s ease;
  }}
  .card:hover {{ border-color: var(--accent); }}
  .top {{
    display: flex; flex-direction: column; align-items: center; gap: .75rem;
    padding: 2.5rem 1.5rem; color: inherit; text-decoration: none;
  }}
  .top:focus-visible {{ outline: 2px solid var(--accent); outline-offset: -2px; }}
  .label {{ font-size: 1rem; font-weight: 500; color: var(--muted); }}
  .version {{
    font: 700 clamp(2.75rem, 7vw, 4rem)/1 ui-monospace, "SF Mono", Menlo, monospace;
    color: var(--accent); letter-spacing: -.02em;
  }}
  .meta {{ font-size: .85rem; color: var(--muted); }}
  .error .version {{ color: var(--critical); }}
  .vulns {{ border-top: 1px solid var(--border); padding: 1rem 1.25rem 1.25rem; }}
  .vhead {{
    font-size: .7rem; font-weight: 600; letter-spacing: .14em; text-transform: uppercase;
    color: var(--critical); margin-bottom: .6rem;
  }}
  .none {{ font-size: .85rem; color: var(--muted); text-align: center; }}
  .vulns ul {{ list-style: none; display: flex; flex-direction: column; gap: .5rem; }}
  .vulns li a {{
    display: flex; gap: .75rem; align-items: flex-start;
    padding: .65rem .75rem; border-radius: 10px;
    background: var(--critical-bg); color: inherit; text-decoration: none;
    font-size: .85rem; line-height: 1.4;
  }}
  .vulns li a:hover .vtitle {{ text-decoration: underline; }}
  .score {{
    flex: none; font: 700 .8rem/1.4 ui-monospace, Menlo, monospace; color: var(--critical);
    min-width: 2.2em; white-space: nowrap;
  }}
  .score.level {{ font: 600 .65rem/1.9 system-ui, sans-serif; letter-spacing: .08em; text-transform: uppercase; }}
  .cve {{ color: var(--muted); font-size: .75rem; white-space: nowrap; }}
  footer {{ display: flex; flex-direction: column; gap: .5rem; font-size: .75rem; color: var(--muted); text-align: center; }}
  footer a {{ color: inherit; }}
  footer .tip {{ color: var(--accent); text-decoration: none; font-weight: 600; }}
  footer .tip:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
  <h1>Latest Stable Release</h1>
  <main class="grid">{cards}
  </main>
  <footer>
    <p>Checked <time datetime="{iso}">{fallback}</time> · Versions from <a href="https://endoflife.date">endoflife.date</a>
      · Vulnerabilities from <a href="https://www.wordfence.com/threat-intel/">Wordfence Intelligence</a>
      and <a href="https://www.drupal.org/security">Drupal Security</a></p>
    <p>Idea &amp; conceptual design by {html.escape(AUTHOR_NAME)} · Code & UI written with Claude
      · <a href="{html.escape(SOURCE_URL)}">Source</a>{tip}</p>
  </footer>
  <script>
    // Show the check time in the visitor's own time zone
    const t = document.querySelector("time");
    t.textContent = new Date(t.dateTime).toLocaleString([], {{dateStyle: "medium", timeStyle: "short"}});
  </script>
</body>
</html>"""


def build_page():
    return render(get_data(), datetime.now(timezone.utc))


# ---------- entry points ----------

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return
        body = build_page().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    if not WORDFENCE_KEY:
        print("Note: WORDFENCE_API_KEY not set — WordPress vulnerabilities will be skipped.", file=sys.stderr)

    if len(sys.argv) == 3 and sys.argv[1] == "--build":
        out = sys.argv[2]
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        with open(out, "w") as f:
            f.write(build_page())
        print(f"Wrote {out}")
    else:
        print(f"Serving on http://localhost:{PORT}  (Ctrl+C to stop)")
        HTTPServer(("", PORT), Handler).serve_forever()
