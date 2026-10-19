"""Run in the approved task copy, then inspect the proposed diff."""
from pathlib import Path
path = Path("message.py")
original = path.read_text(encoding="utf-8")
expected = 'return f"Hello, {name}!"'
if expected not in original:
    raise SystemExit("baseline mismatch")
path.write_text(original.replace(expected, 'return f"Welcome, {name}!"'), encoding="utf-8")
