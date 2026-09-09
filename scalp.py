#!/usr/bin/env python3
"""
    Scalp! Apache log based attack analyzer
    Maintained and Modernized by DragonJAR SAS <https://www.DragonJAR.org>

    Licensed under the Apache License, Version 2.0.
"""
import sys
from scalp.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
