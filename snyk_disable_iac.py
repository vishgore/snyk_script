#!/usr/bin/env python3
"""
Bulk enable/disable Snyk IaC "Detect configuration files" across many Orgs.

THE ENDPOINT (captured from the Snyk web UI, 2026-09-07)

    PUT https://app.snyk.io/org/{ORG_SLUG}/manage/cloud-config/updateDetectCloudConfigFiles
    Accept: application/json
    Content-Type: application/json
    X-Requested-With: XMLHttpRequest
    X-CSRF-Token: <per-session token>
    {"detectCloudConfigFilesEnabled": false}

    Auth is the browser SESSION COOKIE *plus* a CSRF token -- not an API token.
    Cookie alone returns 403; all four headers are required. The CSRF token is
    embedded in any authenticated app.snyk.io page as "csrfToken":"..." inside
    a URL-encoded bootstrap blob. It is session-scoped, not per-org, so this
    script scrapes it once per run and reuses it for every org.

    This is NOT DOM automation -- one HTTP request per org, so 500 orgs takes
    about a minute.

    UNSUPPORTED AND UNDOCUMENTED. This is the private endpoint behind the
    toggle in Org Settings > Snyk IaC. The public REST API has no equivalent:
    /rest/orgs/{id}/settings/iac only carries custom_rules. Snyk can change or
    remove this without notice.

SETUP
    pip install playwright && playwright install chromium

USAGE
    set SNYK_TOKEN=...                          # only for --fetch-orgs
    python disable_iac_ui.py --group <GROUP_ID> --fetch-orgs    # -> orgs.txt
    python disable_iac_ui.py --login                            # -> snyk_session.json
    python disable_iac_ui.py --orgs orgs.txt --dry-run
    python disable_iac_ui.py --orgs orgs.txt --apply
    python disable_iac_ui.py --orgs orgs.txt --apply --enable    # reverse it

    If Chromium can't be installed/run (e.g. a locked-down corporate device
    that only allows Microsoft Edge), add --browser msedge to --login and
    --apply -- Playwright will drive your existing Edge install instead of
    downloading its own Chromium.

CORPORATE TLS PROXY (Zscaler / Netskope / Bluecoat etc.)
    Symptom: "unable to get local issuer certificate"

    Proper fix -- point Node at your corporate root CA, then run normally:
        Windows:  set NODE_EXTRA_CA_CERTS=C:\\path\\to\\corp-root-ca.pem
        macOS:    export NODE_EXTRA_CA_CERTS=/path/to/corp-root-ca.pem

    Quick fix -- skip certificate validation for this run:
        python disable_iac_ui.py --orgs orgs.txt --apply --insecure

    Use --insecure only on a trusted network; it disables cert checking for
    the requests this script makes.

REGIONS
    Non-US tenants: change APP_BASE / API_BASE to your region, e.g.
    https://app.eu.snyk.io + https://api.eu.snyk.io. The `snyk.region` cookie
    in your browser tells you which one you are on (SNYK-US-01 = defaults).

NOTES
  * Needs Org Admin on every org; others come back 403 and are logged.
  * progress.json checkpoints after each org, so runs are resumable.
  * Does NOT delete IaC Projects already imported -- separate job.
  * Session cookies expire. A wall of 403s means re-run --login.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

API_BASE = "https://api.snyk.io"
APP_BASE = "https://app.snyk.io"
REST_VERSION = "2024-10-15"
SESSION_FILE = "snyk_session.json"
PROGRESS_FILE = "progress.json"

ENDPOINT = "{app}/org/{slug}/manage/cloud-config/updateDetectCloudConfigFiles"

CSRF_PATTERNS = [
    r'csrfToken%22%3A%22([A-Za-z0-9_\-]+)%22',
    r'"csrfToken"\s*:\s*"([A-Za-z0-9_\-]+)"',
]

TLS_HINT = (
    "\nTLS error -- your machine is behind a certificate-inspecting proxy.\n"
    "  Fix properly:  set NODE_EXTRA_CA_CERTS=C:\\path\\to\\corp-root-ca.pem\n"
    "  Or bypass:     add --insecure to this command\n"
)


GROUP_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def fetch_orgs(group_id, out_path="orgs.txt"):
    """Org slugs for the group, via the public REST API."""
    token = os.environ.get("SNYK_TOKEN")
    if not token:
        sys.exit("Set SNYK_TOKEN to fetch org slugs.")
    if not GROUP_ID_RE.match(group_id):
        sys.exit(f"--group must be a UUID, got: {group_id!r}")

    slugs, path, params = [], f"/rest/groups/{group_id}/orgs", {"limit": 100}
    while path:
        url = API_BASE + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(
                {**params, "version": REST_VERSION})
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"token {token}")
        with urllib.request.urlopen(req, timeout=60) as r:
            page = json.loads(r.read())
        for o in page.get("data", []):
            if o["attributes"].get("slug"):
                slugs.append(o["attributes"]["slug"])
        path, params = page.get("links", {}).get("next"), None

    with open(out_path, "w") as f:
        f.write("\n".join(slugs) + "\n")
    print(f"{len(slugs)} org slugs -> {out_path}")


def login(insecure, channel=None):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        launch_kwargs = {"headless": False}
        if channel:
            launch_kwargs["channel"] = channel
        browser = p.chromium.launch(**launch_kwargs)
        ctx = browser.new_context(ignore_https_errors=insecure)
        ctx.new_page().goto(f"{APP_BASE}/login")
        input("Log in (SSO/MFA included), land on the dashboard, then press Enter... ")
        ctx.storage_state(path=SESSION_FILE)
        browser.close()
    os.chmod(SESSION_FILE, 0o600)
    print(f"session saved -> {SESSION_FILE}")


def get_csrf(api, probe_slug):
    """Scrape the session CSRF token out of an authenticated page."""
    try:
        resp = api.get(f"{APP_BASE}/registry/org/{probe_slug}/manage/cloud-config",
                       timeout=45000)
    except Exception as e:
        if "issuer certificate" in str(e) or "SSL" in str(e) or "CERT" in str(e).upper():
            sys.exit(TLS_HINT)
        raise
    if resp.status != 200:
        sys.exit(f"Could not load a page to read the CSRF token (HTTP {resp.status}). "
                 f"Session probably expired -- re-run --login.")
    html = resp.text()
    for pat in CSRF_PATTERNS:
        m = re.search(pat, html)
        if m:
            return m.group(1)
    sys.exit("Could not find csrfToken in the page. The UI may have changed; "
             "re-capture it from DevTools (Network > the PUT > x-csrf-token).")


def load_progress():
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE) as f:
            return json.load(f)
    return {}


def run(orgs_path, apply_changes, enable, delay, insecure, channel=None):
    from playwright.sync_api import sync_playwright

    if not os.path.exists(SESSION_FILE):
        sys.exit(f"No {SESSION_FILE}. Run --login first.")
    with open(orgs_path) as f:
        slugs = [ln.strip() for ln in f if ln.strip()]
    if not slugs:
        sys.exit(f"{orgs_path} is empty.")

    target = bool(enable)
    status_label = "enabled" if target else "disabled"
    prog = load_progress()
    todo = [s for s in slugs if prog.get(s) != status_label]

    print(f"{len(slugs)} orgs, {len(todo)} to do | "
          f"detectCloudConfigFilesEnabled -> {target} | "
          f"{'APPLY' if apply_changes else 'DRY RUN'}"
          f"{' | INSECURE TLS' if insecure else ''}\n")

    if not apply_changes:
        for s in todo[:10]:
            print(f"  would PUT {ENDPOINT.format(app=APP_BASE, slug=s)}")
        if len(todo) > 10:
            print(f"  ... and {len(todo)-10} more")
        print(f'\n  body: {{"detectCloudConfigFilesEnabled": {str(target).lower()}}}')
        return

    with sync_playwright() as p:
        launch_kwargs = {"headless": True}
        if channel:
            launch_kwargs["channel"] = channel
        browser = p.chromium.launch(**launch_kwargs)
        ctx = browser.new_context(storage_state=SESSION_FILE,
                                  ignore_https_errors=insecure)
        api = ctx.request                      # shares the session cookie jar

        csrf = get_csrf(api, slugs[0])

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "X-CSRF-Token": csrf,
        }

        for i, slug in enumerate(todo, 1):
            url = ENDPOINT.format(app=APP_BASE, slug=slug)
            try:
                resp = api.put(
                    url,
                    headers={**headers,
                             "Referer": f"{APP_BASE}/registry/org/{slug}"
                                        f"/manage/cloud-config"},
                    data=json.dumps({"detectCloudConfigFilesEnabled": target}),
                    timeout=30000,
                )
                prog[slug] = status_label if resp.status == 200 else f"http-{resp.status}"
            except Exception as e:
                prog[slug] = f"error:{type(e).__name__}"

            with open(PROGRESS_FILE, "w") as f:
                json.dump(prog, f, indent=2)
            print(f"[{i}/{len(todo)}] {slug:45s} {prog[slug]}")
            if delay:
                time.sleep(delay)

        browser.close()

    counts = {}
    for v in prog.values():
        counts[v] = counts.get(v, 0) + 1
    print("\nsummary:", counts)
    if any(k.startswith("http-403") for k in counts):
        print("403 = not Org Admin there, expired session (--login), "
              "or a stale CSRF token (just re-run).")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--group")
    ap.add_argument("--fetch-orgs", action="store_true")
    ap.add_argument("--login", action="store_true")
    ap.add_argument("--orgs", default="orgs.txt")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--enable", action="store_true",
                    help="turn detection back ON instead of off")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS cert validation (corporate proxy workaround)")
    ap.add_argument("--browser", choices=["chromium", "msedge"], default="chromium",
                    help="browser Playwright drives -- use msedge if Chromium "
                         "can't be installed/run (e.g. locked-down corporate "
                         "device); requires Microsoft Edge to already be "
                         "installed")
    ap.add_argument("--delay", type=float, default=0.2)
    args = ap.parse_args()
    channel = None if args.browser == "chromium" else args.browser

    if args.fetch_orgs:
        if not args.group:
            sys.exit("--fetch-orgs needs --group")
        fetch_orgs(args.group)
    elif args.login:
        login(args.insecure, channel)
    elif args.dry_run or args.apply:
        run(args.orgs, args.apply, args.enable, args.delay, args.insecure, channel)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
