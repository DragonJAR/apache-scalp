#!/usr/bin/env python3
"""
    Scalp! Apache log based attack analyzer
    by Romain Gaucher <r@rgaucher.info> - http://rgaucher.info
    Maintained and Modernized by DragonJAR SAS <https://www.DragonJAR.org>

    Licensed under the Apache License, Version 2.0.
"""
import sys
from pathlib import Path

# Ensure package root is in sys.path when executed directly
pkg_root = Path(__file__).resolve().parent.parent
if str(pkg_root) not in sys.path:
    sys.path.insert(0, str(pkg_root))

from scalp.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
