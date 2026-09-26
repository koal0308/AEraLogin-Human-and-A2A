#!/bin/sh
# Negative proof: temporarily remove two security checks from the LOCAL
# verifier and confirm that the security test suite actually fails.
# The production Agent Identity Layer is NOT touched by this script.
set -e
cd "$(dirname "$0")/.."
PY=../venv/bin/python
cp src/a2a/protocol.py /tmp/proto.orig

$PY - <<'EOF'
p = 'src/a2a/protocol.py'
s = open(p).read()
a = '''        if content_hash(env.content) != p["content_hash"]:
            raise LocalVerificationError("content_hash_mismatch")'''
b = '''        if not verify_signature(k["public_key"], env.signature, canon):
            raise LocalVerificationError("message_signature_invalid")'''
assert s.count(a) == 1, "content_hash check not found"
assert s.count(b) == 1, "signature check not found"
s = s.replace(a, '        pass  # TEMP-VULN-content-hash', 1)
s = s.replace(b, '        pass  # TEMP-VULN-signature', 1)
open(p, 'w').write(s)
print("checks removed")
EOF

echo "=== suite WITH the checks removed (must FAIL) ==="
set +e
$PY -m pytest tests -q 2>&1 | tail -n 3
set -e

cp /tmp/proto.orig src/a2a/protocol.py
rm -f /tmp/proto.orig
echo "=== suite restored (must PASS) ==="
$PY -m pytest tests -q 2>&1 | tail -n 2
