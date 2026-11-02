#!/usr/bin/env python3
"""
Automated IAM Governance & Drift Detection Engine - Root CLI
"""
import sys
from src.main import main

if __name__ == "__main__":
    # If no arguments are passed, default to running a full governance scan
    if len(sys.argv) == 1:
        sys.argv.append("--scan")
    sys.exit(main())
