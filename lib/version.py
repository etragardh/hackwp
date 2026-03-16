"""
HWP Version - Parse and compare version ranges.

Formats:
    "* - 1.9.6"        up to and including 1.9.6
    "1.1.1 - 1.2.2"    between (inclusive)
    "1.2.3"             exactly this version
    "*"                 any version
"""

import re
from packaging.version import Version, InvalidVersion


def parse_range(version_str):
    version_str = version_str.strip()
    if version_str == "*":
        return (None, None)

    match = re.match(r"^(\*|\S+)\s*-\s*(\*|\S+)$", version_str)
    if match:
        low, high = match.group(1), match.group(2)
        low_v = None if low == "*" else Version(low)
        high_v = None if high == "*" else Version(high)
        return (low_v, high_v)

    return (Version(version_str), Version(version_str))


def version_in_range(version_str, range_str):
    try:
        version = Version(version_str)
        low, high = parse_range(range_str)
    except (InvalidVersion, ValueError):
        return False

    if low is not None and version < low:
        return False
    if high is not None and version > high:
        return False
    return True
