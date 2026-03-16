"""
HWP Loader - Discovers and loads exploit/payload classes from the filesystem.

Exploit path: exploits/{slug}/{version-cap}/main.py
Payload path: payloads/{name}/main.py
"""

import os
import sys
import importlib.util
from lib.exploit import Exploit
from lib.payload import Payload
from lib import output


def _load_class_from_file(filepath, base_class):
    """Load a Python file and return the first subclass of base_class."""
    # Ensure hwp root is on sys.path so `from hwp import ...` works
    hwp_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if hwp_root not in sys.path:
        sys.path.insert(0, hwp_root)

    spec = importlib.util.spec_from_file_location("_hwp_module", filepath)
    if spec is None:
        output.error(f"Cannot load: {filepath}")
        return None

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        output.error(f"Error loading {filepath}: {e}")
        return None

    for attr_name in dir(module):
        attr = getattr(module, attr_name)
        if (isinstance(attr, type)
                and issubclass(attr, base_class)
                and attr is not base_class):
            return attr

    output.error(f"No {base_class.__name__} subclass found in {filepath}")
    return None


def load_exploit(exploit_ref, exploits_dir):
    """
    Load exploit by ref string like 'bricks/1.9.6-rce'.
    Maps to: exploits_dir/bricks/1.9.6-rce/main.py
    """
    filepath = os.path.join(exploits_dir, exploit_ref, "main.py")
    if not os.path.isfile(filepath):
        output.error(f"Exploit not found: {filepath}")
        return None
    return _load_class_from_file(filepath, Exploit)


def load_payload(payload_ref, payloads_dir):
    """
    Load payload by ref string like 'shell'.
    Maps to: payloads_dir/shell/main.py
    """
    filepath = os.path.join(payloads_dir, payload_ref, "main.py")
    if not os.path.isfile(filepath):
        output.error(f"Payload not found: {filepath}")
        return None
    return _load_class_from_file(filepath, Payload)


def list_exploits(exploits_dir):
    """List all available exploit refs."""
    results = []
    if not os.path.isdir(exploits_dir):
        return results
    for slug in sorted(os.listdir(exploits_dir)):
        slug_dir = os.path.join(exploits_dir, slug)
        if not os.path.isdir(slug_dir) or slug.startswith("."):
            continue
        for version_dir in sorted(os.listdir(slug_dir)):
            main_path = os.path.join(slug_dir, version_dir, "main.py")
            if os.path.isfile(main_path):
                results.append(f"{slug}/{version_dir}")
    return results


def list_payloads(payloads_dir):
    """List all available payload refs."""
    results = []
    if not os.path.isdir(payloads_dir):
        return results
    for name in sorted(os.listdir(payloads_dir)):
        main_path = os.path.join(payloads_dir, name, "main.py")
        if os.path.isfile(main_path) and not name.startswith("."):
            results.append(name)
    return results
