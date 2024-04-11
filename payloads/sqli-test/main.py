import os

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
# Return the code to execut
# or the file path to be uploaded
def detonate(vuln, args):
    if vuln == 'SQLi':
        # If we have SQLi
        if args.pos:
            return args.pos
        else:
            return [
                "SELECT count(*) FROM wp_users;",
            ]
