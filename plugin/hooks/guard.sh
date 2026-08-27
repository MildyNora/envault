#!/bin/bash
# envault PreToolUse guard: pipes hook JSON to `envault guard-check`.
# Fail open if envault isn't installed — a half-installed plugin must not
# block the session.
command -v envault >/dev/null 2>&1 || exit 0
exec envault guard-check
