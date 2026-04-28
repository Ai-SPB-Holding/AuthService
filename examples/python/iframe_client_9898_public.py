#!/usr/bin/env python3
"""Demo client: public OAuth app on http://127.0.0.1:9898 (iframe login).

Run from `examples/python` after setting env (see README_iframe_demo.md).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from iframe_demo_common.app import run_demo
from iframe_demo_common.settings import DemoSettings

if __name__ == "__main__":
    run_demo(DemoSettings.load_public_9898())
