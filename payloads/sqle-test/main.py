import os

##
# Dependency
# What dependency does this payload have
def get_methods():
    return ['SQLe']

##
# Detonate payload
# Return the code to execut
# or the file path to be uploaded
def get_instructions(method, args):
    if method == 'SQLe':
        # If we have SQLe
        if args.pos:
            return args.pos
        else:
            return [
                "SELECT count(*) FROM wp_users;",
            ]
##
# Author of this payload
def get_author():
    return "@etragardh"

##
# Special thanks to:
def get_thanks():
    return False

