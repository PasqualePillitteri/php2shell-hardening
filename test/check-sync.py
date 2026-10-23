#!/usr/bin/env python3
# The container test runs a standalone nginx.conf, so its maps can drift from the ones in
# nginx/php2shell-maps.conf. This compares them and fails when they differ.
import re, sys, pathlib

HERE = pathlib.Path(__file__).resolve().parent
SHIPPED = HERE.parent / "nginx" / "php2shell-maps.conf"
TEST = HERE / "nginx-test.conf"

def maps(path):
    text = re.sub(r'(?m)^\s*#.*$', '', path.read_text(encoding="utf-8"))
    out = {}
    for m in re.finditer(r'map\s+(\S+(?:\s+\S+)?)\s*\{(.*?)\}', text, re.S):
        key, body = m.group(1), m.group(2)
        out[" ".join(key.split())] = [" ".join(l.split()) for l in body.split(";") if l.strip()]
    return out

a, b = maps(SHIPPED), maps(TEST)
fail = 0
for name, lines in a.items():
    if name not in b:
        print(f"[FAIL] {name}: missing from {TEST.name}"); fail += 1
    elif b[name] != lines:
        print(f"[FAIL] {name}: differs\n  shipped: {lines}\n  test:    {b[name]}"); fail += 1
    else:
        print(f"[OK] {name}")
print("\nRESULT:", "PASS" if fail == 0 else f"FAIL ({fail})")
sys.exit(1 if fail else 0)
