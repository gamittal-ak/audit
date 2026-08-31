#!/usr/bin/env python3
"""Generate a bcrypt hash for use as APP_PASSWORD in .env"""
import sys

import bcrypt


def main():
    if len(sys.argv) != 2:
        print("Usage: python hash_password.py <password>")
        sys.exit(1)
    hashed = bcrypt.hashpw(sys.argv[1].encode("utf-8"), bcrypt.gensalt())
    print(hashed.decode("utf-8"))


if __name__ == "__main__":
    main()
