# hackwp

This is a work in progress. It is not ready yet.
The main idea is to create a tool that combines the best from `wpscan` and `msf` to be used by pentesters, webmasters and sysadmins to test their own sites, equipment and infrastructure.

I will create both exploits and payloads as I see fit but it would be very much appreciated if the community would help with that.

## Usage

**Installation**

This might be updated before final release to run without pyinstaller
```
gh repo clone etragardh/hackwp
cd hackwp
pyinstaller hackwp.py
ln -s dist/hackwp/hackwp.py /usr/local/bin/hackwp
```

To something like this maybe?
```
gh repo clone etragardh/hackwp
ln -s hackwp/hackwp.py /usr/local/bin/hackwp
```

## Supported/tested platforms
Im running MacOS, Kali and Parrot on my laptop.
These are the tested systems and there should be very few compatibility issues.

However hackwp is written in python and should run fine on most linux.
Let me know if it does not run on any of these and I will try to fix it.

+ macos (tested)
+ kali (tested)
+ parrot (tested)
+ ubuntu/debian
+ arch
+ redhat
+ centos

**Help**
```
hackwp --help
```

## Responsibility and Liability
This software is provided "as is" and is created for educational and testing purposes only. Do not use it for any illegal activities. I will not be held responsible for any harm caused by utilizing this tool in a way it was not meant to.


## Support
<p><a href="https://www.buymeacoffee.com/etragardh"> <img align="left" src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" alt="etragardh" /></a></p>
