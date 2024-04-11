# Smitka Browser (Mini File Browser/mfb)
This is a mini file browser. Single file.
It also reports if dangerous functions is present in PHP
https://github.com/lynt-smitka/PHP-Mini-File-Browser

# HackWP - Server Manager
This is a work in progress. The main idea come from smitka-browser
however this is more modern, easy to use and also includes some dangerous
payloads to be detonated on the server
* Install phpinfo
* Check for dangerous PHP functions
* Try to bypass open_basedir and disable_functions (maybe inlclude Chankro and set it up based on the target)
* Try to escalate to root (search for setuid etc)
* Try to reach sibling sites on the same server
* Try to reach other files on the filesystem
* Create admin users
* Login as other admin, without creating a new admin in DB (See lynt admin)
* Place reverse shell
* Check to see if we can find backups
* Check to see if we can reach private ssh keys
* Check to see if we can insert new public ssh keys

# Lynt Admin
https://gist.github.com/lynt-smitka/0d390a55967fb937218196cd705f80a0

# Create Admin Account
RCE   - insert admin user + give admin privs in user_meta
SQLi  - SQL to create admin + SQL to insert privs in user_meta

# 
