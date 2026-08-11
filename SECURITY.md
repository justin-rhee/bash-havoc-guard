# Security policy - bash-havoc-guard

## Posture

bash-havoc-guard is provided as-is, with NO WARRANTY (see LICENSE). It reduces the
risk of an AI agent running a dangerous shell command; it does not eliminate it.

The honest ceiling: this is a cheap first layer, not a sandbox. It is porous against
deliberate obfuscation (`base64`, `eval`, hiding a path in a variable), and it does
not resolve `..` in paths, so a crafted path can slip a check. It is a blocklist, so
a dangerous command shaped in a way it doesn't recognize can get through. And it only
guards the `Bash` tool. Treat it as a layer that stops honest mistakes and obvious
attacks, in front of an OS-level sandbox, never as the last line of defense.

By design it has no agent override and it fails open (a broken guard allows the
command rather than blocking every command and wedging the session). Both are
deliberate, and both are explained in docs/ADR.md.

## Validation status

The offline suite `tests/test-bash-havoc-guard.sh` runs without network or keys and
passes 24/24: safe commands allowed (including the fingerprint and counting-grep
cases), dangerous commands blocked across all three locks, and the fail-open paths.
Run it before relying on the tool:

    bash tests/test-bash-havoc-guard.sh

## Reporting a vulnerability

If you find a bypass, please report it privately through this repository's
**Security > Report a vulnerability** tab (GitHub private vulnerability reporting)
rather than opening a public issue, so there's time for a fix first. Bypass reports
are especially welcome; this tool is only as good as the reviews that try to beat it.
