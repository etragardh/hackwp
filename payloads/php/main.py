"""
HWP Payload — PHP Code

Execute arbitrary PHP code on the target.
Only works with RCE (PHP execution) capability.

Options:
    --code      PHP code to execute (required, without <?php ?> tags)
"""

from hwp import Payload


class PHPCode(Payload):
    name = "PHP Code"
    methods = ["RCE"]
    description = "Execute arbitrary PHP code on the target"
    options = [
        {"name": "code", "default": "", "help": "PHP code to run (without <?php ?> tags)", "required": True},
    ]

    def instructions(self):
        code = self.options.get("code", "")
        if not code:
            self.error("CODE is required")
            return []

        self.info(f"Executing PHP: {code[:80]}{'…' if len(code) > 80 else ''}")
        return [f"<?php {code} ?>"]

    def report(self, results):
        for r in results:
            if r.success and r.output:
                self.success("Output:")
                print(r.output)
