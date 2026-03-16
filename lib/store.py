"""
HWP Session Store - Persists sessions and credentials to ~/.hackwp/sessions/
"""

import json
import os

SESSIONS_DIR = os.path.join(os.path.expanduser("~/.hackwp"), "sessions")


def _ensure_dir(domain):
    domain_dir = os.path.join(SESSIONS_DIR, domain)
    os.makedirs(domain_dir, exist_ok=True)
    return domain_dir


def _session_path(domain):
    return os.path.join(SESSIONS_DIR, domain, "session.json")


def _credentials_path(domain):
    return os.path.join(SESSIONS_DIR, domain, "credentials.json")


def save_session(domain, cookies):
    _ensure_dir(domain)
    with open(_session_path(domain), "w") as f:
        json.dump(cookies, f, indent=2)


def load_session(domain):
    path = _session_path(domain)
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return None


def save_credentials(domain, credentials):
    _ensure_dir(domain)
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
