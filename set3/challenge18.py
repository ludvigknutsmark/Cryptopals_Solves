#!/usr/bin/python
import base64, struct

# Own imports
from aes_ctr import aes_ctr

Nonce = struct.pack('<Q', 0)
key = "YELLOW SUBMARINE"

base = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
plain = aes_ctr(key, Nonce, base)

print plain
