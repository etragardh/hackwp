"""
HWP Session Store - Persists sessions and credentials to ~/.hwp/
"""

import json
import os

HWP_DIR = os.path.expanduser("~/.hwp")


def _ensure_dir():
    os.makedirs(HWP_DIR, exist_ok=True)


def _session_path(domain):
    return os.path.join(HWP_DIR, f"{domain}.session")


def _credentials_path(domain):
    return os.path.join(HWP_DIR, f"{domain}.credentials")


def save_session(domain, cookies):
    _ensure_dir()
    with open(_session_path(domain), "w") as f:
        json.dump(cookies, f, indent=2)


def load_session(domain):
    path = _session_path(domain)
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return None


def save_credentials(domain, credentials):
    _ensure_dir()
    with open(_credentials_path(domain), "w") as f:
        json.dump(credentials, f, indent=2)


def load_credentials(domain):
    path = _credentials_path(domain)
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return None


def clear(domain):
    for path in [_session_path(domain), _credentials_path(domain)]:
        if os.path.exists(path):
            os.remove(path)
