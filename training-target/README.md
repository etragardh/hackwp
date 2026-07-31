# HWP Training Target

[![HackWP](https://img.shields.io/badge/hackwp.io-Training-orange)](https://hackwp.io)
[![License](https://img.shields.io/badge/use-authorized%20testing%20only-red)](https://github.com/etragardh/hackwp)

Dockerized, isolated, intentionally vulnerable WordPress lab for [HackWP](https://github.com/etragardh/hackwp) security training.

> **⚠ WARNING: This is an INTENTIONALLY VULNERABLE WordPress instance for local
> testing only. Every endpoint is a real vulnerability. Do NOT expose it to the
> internet or any untrusted network.** The published ports bind to `127.0.0.1`
> only, so it is reachable from your machine but not your LAN.

## Quick Start

```bash
cd training-target
docker compose up -d
```

Wait ~30 seconds for setup to complete. Check progress:

```bash
docker logs -f hwp-wpcli
```

## Access

| Service     | URL                                  | Credentials            |
|-------------|--------------------------------------|------------------------|
| WordPress   | http://localhost                      | —                      |
| WP Admin    | http://localhost/wp-admin             | admin / admin          |
| phpMyAdmin  | http://localhost:8080                 | root / rootpass        |
| REST API    | http://localhost/wp-json/hwp-training/v1/ | —               |

### Test Users

| Username   | Password   | Role          |
|------------|------------|---------------|
| admin      | admin      | Administrator |
| editor     | editor     | Editor        |
| author     | author     | Author        |
| subscriber | subscriber | Subscriber    |

## Vulnerability Endpoints

One endpoint per HWP capability (1:1), named after the capability, all under
`/wp-json/hwp-training/v1/`. Each has a matching exploit at
`exploits/hwp-training/1.0.0-<capability>/`.

| Endpoint    | Method   | Capability | Description                               |
|-------------|----------|------------|-------------------------------------------|
| `/rce`      | POST     | RCE        | eval() — `code` param                     |
| `/lfi`      | POST     | LFI        | file_get_contents() — `file` param        |
| `/afu`      | POST     | AFU        | unrestricted upload — `file` multipart    |
| `/rfi`      | POST     | RFI        | fetch URL + include — `url` param         |
| `/sqli`     | POST     | SQLI       | $wpdb->query() write — `sql` param        |
| `/sqliq`    | POST     | SQLIq      | $wpdb->get_results() read — `sql` param   |
| `/codeinj`  | POST     | CODEINJ    | deferred PHP include — `code` param       |
| `/xss`      | POST/GET | XSS        | stored XSS via option — `payload` param   |
| `/xssr`     | GET      | XSSr       | reflected XSS — `q` param                 |
| `/objinj`   | POST     | OBJINJ     | unserialize() — `data` param              |
| `/afd`      | POST     | AFD        | unlink() by path — `file` param           |
| `/filedl`   | GET      | FILEDL     | readfile() by path — `file` param         |
| `/auth`     | POST     | AUTH       | create admin session — optional user/pass |
| `/privesc`  | POST     | PRIVESC    | logged-in user → admin (auth required)    |
| `/other`    | GET      | OTHER      | config leak, no chain payload             |

## POP Gadget (OBJINJ)

`HWP_Training_Gadget_RCE` — `eval()` in `__destruct`. The
`hwp-training/1.0.0-pop-rce` transformer serialises attacker PHP into this gadget;
delivering it through `/objinj` (unserialize) triggers RCE.

## HWP Usage

```bash
# Scan
hwp -t localhost --scan

# RCE (payload emits PHP; a shell-only sink would wrap php -r itself)
hwp -t localhost --exploit hwp-training/1.0.0-rce --payload bash --cmd "whoami"
hwp -t localhost --exploit hwp-training/1.0.0-rce --payload webshell

# File upload / read / download / delete
hwp -t localhost --exploit hwp-training/1.0.0-afu --payload webshell
hwp -t localhost --exploit hwp-training/1.0.0-lfi --payload file_read --file /etc/passwd
hwp -t localhost --exploit hwp-training/1.0.0-filedl --payload file_read --file /etc/passwd
hwp -t localhost --exploit hwp-training/1.0.0-afd --file /var/www/html/wp-content/uploads/x.txt

# SQL injection — write (SQLI) vs read (SQLIq)
hwp -t localhost --exploit hwp-training/1.0.0-sqli --payload admin_user
hwp -t localhost --exploit hwp-training/1.0.0-sqliq          # dumps wp_users hashes

# Auth, then privilege escalation from a low-priv session
hwp -t localhost --exploit hwp-training/1.0.0-auth hwp-training/1.0.0-rce --payload bash --cmd "id"
hwp -t localhost --exploit hwp-training/1.0.0-privesc --user subscriber --pass subscriber

# Object injection via the POP-chain transformer
hwp -t localhost --exploit hwp-training/1.0.0-objinj hwp-training/1.0.0-pop-rce --payload php --code "phpinfo();"

# Reflected XSS — the framework prints + copies a URL for you to open in a browser
hwp -t localhost --exploit hwp-training/1.0.0-xssr

# Stored XSS escalated to RCE via the adapter
hwp -t localhost --exploit hwp-training/1.0.0-xss --payload webshell --xss-rce-adapter
```

## Configuration

All settings are in `.env`. Defaults work out of the box:

```bash
WP_PORT=80              # WordPress port
PMA_PORT=8080           # phpMyAdmin port
WP_URL=http://localhost # Must match WP_PORT

WP_ADMIN_USER=admin
WP_ADMIN_PASSWORD=admin

WORDPRESS_DB_NAME=wordpress
WORDPRESS_DB_USER=wordpress
WORDPRESS_DB_PASSWORD=wordpress
MARIADB_ROOT_PASSWORD=rootpass
```

Custom port example:

```bash
WP_PORT=9090
WP_URL=http://localhost:9090
```

After changing `.env`, reset with `docker compose down -v && docker compose up -d`.

## Reset

```bash
# Full reset (nuke all data)
docker compose down -v
docker compose up -d

# Just restart services
docker compose restart
```

## Architecture

```
hwp-training-target/
├── docker-compose.yml                 # Service definitions
├── .env                               # Configuration (ports, credentials)
├── .env.example                       # Template for .env
├── setup.sh                           # WP-CLI setup script
├── config/
│   └── php.ini                        # Permissive PHP settings
├── mu-plugins/
│   ├── hwp-training-target.php        # The vulnerable mu-plugin
│   └── hwp-training-target/
│       ├── style.css                  # Detection CSS for WPScanX
│       └── injected.php               # CODEINJ target file
└── README.md
```

## License

GNU General Public License v3.0.

## Disclaimer

This environment is for **authorized security testing and educational purposes only**.
Do not expose to the internet. Do not use against systems you don't own.
