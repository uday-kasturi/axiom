#!/usr/bin/env python3
"""
Smoke test for the MuseSparkClient adapter.
Run AFTER grab_muse_auth.py has captured a message-sending mutation.

Usage:
  python test_muse_adapter.py
  python test_muse_adapter.py "say hello in one sentence"
"""
import sys
from target.profiler import MuseSparkClient

message = sys.argv[1] if len(sys.argv) > 1 else "Say the word 'pineapple' and nothing else."

print(f"Probe: {message!r}")
print("-" * 60)

try:
    client = MuseSparkClient()
    print(f"doc_id:    {client._doc_id}")
    print(f"var keys:  {list(client._var_template.keys())}")
    print(f"msg key:   {client._find_msg_key(client._var_template)!r}")
    print("-" * 60)
    response = client.send(message)
    print("Response:")
    print(response)
except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")
    sys.exit(1)
