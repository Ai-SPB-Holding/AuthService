#!/usr/bin/env python3
"""Print current TOTP (6 digits) from base32 secret. RFC 6238, SHA1, 30s step."""
import base64
import hmac
import hashlib
import struct
import sys
import time


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: totp_code.py <secret_base32>", file=sys.stderr)
        sys.exit(1)
    secret_b32 = sys.argv[1].strip().replace(" ", "").upper()
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32 + pad)
    counter = int(time.time()) // 30
    msg = struct.pack(">Q", counter)
    dig = hmac.new(key, msg, hashlib.sha1).digest()
    off = dig[-1] & 0x0F
    n = struct.unpack(">I", dig[off : off + 4])[0] & 0x7FFFFFFF
    print(f"{n % 1_000_000:06d}")


if __name__ == "__main__":
    main()
