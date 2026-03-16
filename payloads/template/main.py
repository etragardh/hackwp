"""
HWP Payload Template
Copy this folder and modify to create your own payload.

Folder structure:
    payloads/<name>/main.py

Example:
    payloads/my_payload/main.py
"""

from hwp import Payload


class MyPayload(Payload):
    name = "My Payload"
    methods = ["RCE"]           # Which exploit capabilities I work with
    description = "Describe what this payload does"

    def instructions(self):
        """
        Return a list of instruction strings for the given method.

        Available context:
            self.target     — Base URL
            self.domain     — Domain string
            self.options    — Extra CLI args (e.g. self.options.get("lhost"))

        Placeholders (resolved by framework between instructions):
            {prev.output}        — Output from previous instruction
            {prev.insert_id}     — Insert ID from previous SQL instruction
            {prev.rows_affected} — Rows affected by previous SQL instruction
        """
        if self.method == "RCE":
            return ["<?php echo 'Hello from my payload'; ?>"]

    def report(self, results):
        """Optional: print a summary after all instructions have run."""
        for r in results:
            if r.success:
                self.success("It worked!")
