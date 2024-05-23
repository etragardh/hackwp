# HackWP

This is a tool Im using to offload heavy work from WP pentesting.<br />
IE for me to re use payloads, use stolen cookies, spoof IPs etc.<br />
<br />
The main idea with open sourceing this is to release a tool that combines the best from `wpscan` and `msf` to be used by pentesters, webmasters and sysadmins to test their own sites, equipment and infrastructure.

I will probably opensource most of my exploits with time but it is very welcome if the community would add their own. Create a pull request and I will add it if it is nice.

>[!CAUTION]
> Be careful when using HackWP.<br />
> This is an agressive tool that presumes you are the admin/owner of the site you are pentesting.
> If you don't have the option to white list your IP in your firewall you can use a VPN. Proxies are currently not supported :/

## Usage

**Installation**

```
gh repo clone etragardh/hackwp
chmod +x hackwp/hackwp
sudo ln -s ${PWD}/hackwp/hackwp /usr/local/bin
```

**Update**

```
cd /path/to/hackwp/
git pull
```

**Sample Scan**
```
hackwp --scan --target http://localhost --spoof
hackwp --scan --target http://localhost --spoof --verbose <- more info
hackwp --scan --target http://localhost --spoof --debug <- most info
```

**Sample hacks**

Test payload
```
hackwp --target http://localhost --attack bricks --exploit 1.9.6-rce --payload test-rce --spoof --debug
```
Test payload with manual PHP
```
hackwp --target http://localhost --attack bricks --exploit 1.9.6-rce --payload test-rce "<?php echo DB_PASSWORD; ?>"  --spoof --debug
```

**What commands to run**

HackWP will tell you what commands are available after the scan is complete. It will tell you what exploits will work with the scanned site and give you a command to copy/paste.

You can also list available exploits and payloads like this.<br />
+TODO: List command is not implemented since there are only a few options
```
hackwp --list <exploits|payloads> <method|surface|author>
hackwp --list exploits <- all exploits
hackwp --list exploits rce <- exploits that has RCE
hackwp --list exploits bricks <- exploits that affects bricks surface
hackwp --list payloads <- all payloads
```

## Roadmap
+ Interesing findings<br />
+ Password spray on enumerated users<br />
+ Stess test reflected DDoS<br />
+ Stess test amplified Dos/DDoS<br />
+ Better error handling<br />
+ Performance and memory management<br />
+ Documentation<br />
+ Auto test any input for reflected XSS<br />
+ Enumerate emails<br />

## Documentation
[Documentation](https://github.com/etragardh/hackwp/tree/main/docs/)
[Create Exploit](https://github.com/etragardh/hackwp/tree/main/docs/exploit/)
[Create Payload](https://github.com/etragardh/hackwp/tree/main/docs/payload)

## Dependencies

+TODO: Update list of deps<br />
+TODO: Auto install deps with pip if available<br />

## Performance
+TODO: add support for multi threading<br />
(To many, to quick, live requests might get you banned, but handling cached scans can increase performance a lot if multi threaded)<br />
+TODO: Memory management.<br />
(Go through the code and make sure file pointers are closed, files/content released from memory when not used etc)<br />
+TODO: Limit the amount of requests when crawling the local site.<br />
(A large site with thousands of pages takes a long time to scan)

## Stealth

**Spoofing**
You can have HackWP spoof your IP.
That will trick most of the Wordpress "get true IP" functions but it will not trick the Police, FBI or other authority that wants to know who you are.

```
hackwp --scan --target http://localhost --spoof <- spoof IP and UA
hackwp --scan --target http://localhost --spoof-ip <- spoof IP only 
hackwp --scan --target http://localhost --spoof-ua <- spoof UA only
```

**Proxy**
+TODO: Add proxy support for some thing like this:<br />
[Proxyrack](https://www.proxyrack.com/)
This means every request can have a unique IP and it is not needed to spoof it.

**VPN**
You can connect your computer to a VPN and then run HackWP. The connection will go through your VPN provider.

**TOR**
+TODO: Add support for Onion Routing so requests can have unique IPs andprevent trace backwards.

## Supported/tested platforms
Im running MacOS, Kali and Parrot on my laptop.
These are the tested systems and there should be very few compatibility issues.

However hackwp is written in python and should run fine on most linux.
Let me know if it does not run on any of these and I will try to fix it.

+ macos (tested)
+ kali (tested)
+ parrot (tested)
+ ubuntu/debian

**Help**
CLI Help
```
hackwp --help
```

Help is also available in the blueteamer discord server.
`https://discord.gg/mNQ66EdJkE`

## Agressive scanning
HackWP is pretty agressive in its nature.<br />
However we have an agressive option that makes the scan truly agressive.

Before using this option, make sure you are behind a VPN, Proxy or that your IP is white listed in the firewall. You might get banned for doing a lot of requests.

```
hackwp --scan --target http://localhost --agressive
```

Will add the following to the scan:<br />
+ Test all vulnerable plugins one by one
normally plugins are detected just by scanning the source code
+ Add cryptographic signatures as an option to WP Core Version scan
(will yield more requests to files that might be blocked by cloudflare or other external firewall zero trust policies)

## Cache

HackWP has caching. It scans/crawl the entire target webiste once. Then the cache is re used for other tasks.
If you think the site has changed or that some requests were cached in the wrong state (ie you got banned and have now changed IP) you can purge the cache.
```
hackwp --scan --target http://localhost --purge
```


## Responsibility and Liability
This software is provided "as is" and is created for educational and testing purposes only. Do not use it for any illegal activities. I will not be held responsible for any harm caused by utilizing this tool in a way it was not meant to.


## Support
<p><a href="https://www.buymeacoffee.com/etragardh"> <img align="left" src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" alt="etragardh" /></a></p>
