"""
Entrypoint script loaded by mitmproxy via `-s`.
"""

import sys
from pathlib import Path

package_parent = Path(__file__).resolve().parent.parent
if str(package_parent) not in sys.path:
    sys.path.insert(0, str(package_parent))

from mitmproxy_addon.addon import addons

__all__ = ["addons"]
