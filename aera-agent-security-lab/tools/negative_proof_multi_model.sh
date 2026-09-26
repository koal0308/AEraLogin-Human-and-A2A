#!/bin/sh
# Negative proof for the multi-model tests: remove real protections and
# confirm the new MODEL-* tests actually fail. Always restores the sources.
set -e
cd "$(dirname "$0")/.."

PY=../venv/bin/python
cp src/a2a/protocol.py /tmp/np_protocol.bak
cp src/providers/claude.py /tmp/np_claude.bak
cp src/providers/registry.py /tmp/np_registry.bak

restore() {
  cp /tmp/np_protocol.bak src/a2a/protocol.py
  cp /tmp/np_claude.bak   src/providers/claude.py
  cp /tmp/np_registry.bak src/providers/registry.py
}
trap restore EXIT INT TERM

$PY - <<'PY'
import pathlib

def patch(path, pairs):
    p = pathlib.Path(path)
    s = p.read_text()
    for old, new in pairs:
        assert s.count(old) >= 1, (path, old)
        s = s.replace(old, new)
    p.write_text(s)

# 1. receiver no longer rebinds content to its hash  -> MODEL-16 must fail
# 2. receiver no longer checks who sent it           -> MODEL-13/14/15 must fail
patch("src/a2a/protocol.py", [
    ('raise LocalVerificationError("content_hash_mismatch")', 'pass  # MUTANT'),
    ('raise LocalVerificationError("sender_mismatch")', 'pass  # MUTANT'),
])

# 3. Claude thinking no longer disabled -> MODEL-03b must fail
patch("src/providers/claude.py", [
    ('if not self.extended_thinking:\n            body["thinking"] = {"type": "disabled"}',
     'pass  # MUTANT'),
])

# 4. registry accepts anything -> MODEL-17 must fail
patch("src/providers/registry.py", [
    ('f"unknown provider {name!r}; available: {\', \'.join(PROVIDER_NAMES)}"',
     '"mutant"'),
])
print("mutations applied")
PY

echo "--- mutated (expect FAILURES) ---"
$PY -m pytest tests/integration tests/unit/test_multi_model.py -q 2>&1 | tail -5 || true

restore
trap - EXIT INT TERM
echo "--- restored (expect all pass) ---"
$PY -m pytest tests/integration tests/unit/test_multi_model.py -q 2>&1 | tail -5
