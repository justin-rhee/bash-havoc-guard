# Security policy - bash-havoc-guard

## Posture

bash-havoc-guard is provided as-is, with NO WARRANTY (see LICENSE). It reduces the
risk of an AI agent running a dangerous shell command; it does not eliminate it.

The honest ceiling: this is a cheap first layer, not a sandbox. It is porous against
deliberate obfuscation (`base64`, `eval`, hiding a path in a variable), and it does
not resolve `..` in paths, so a crafted path can slip a check. It is a blocklist, so
a dangerous command shaped in a way it doesn't recognize can get through. And it only
guards the `Bash` tool.

Known bypass class: interpreters. A one-liner such as `python3 -c`, `node -e`, `perl -e`
or `ruby -e` whose quoted code names a real credential store (`.ssh`, `.aws`, `id_rsa`,
`.env` and the rest of the hard list) is blocked. Everything else an interpreter can do
is not: a script file that reads the key, a heredoc fed to `python3 -`, a path assembled
from pieces, or a read through a language the list does not name all pass, because a
program can always open a file. Only an OS sandbox closes this. Treat it as a layer that stops honest mistakes and obvious
attacks, in front of an OS-level sandbox, never as the last line of defense.

By design it has no agent override and it fails open (a broken guard allows the
command rather than blocking every command and wedging the session). Both are
deliberate, and both are explained in docs/ADR.md.

## Validation status

The offline suite `tests/test-bash-havoc-guard.sh` runs without network or keys and
passes 142/142 (run on bash 5.2 with `jq` installed): safe commands allowed
(including the fingerprint and counting-grep cases), dangerous commands blocked across
all three locks, interpreter one-liners that name a credential path, and the fail-open
paths. It does not cover real agent sessions, Windows, or the bypasses listed above.
Run it before relying on the tool:

    bash tests/test-bash-havoc-guard.sh

## Reporting a vulnerability

If you find a bypass, please report it privately through this repository's
**Security > Report a vulnerability** tab (GitHub private vulnerability reporting)
rather than opening a public issue, so there's time for a fix first. Bypass reports
are especially welcome; this tool is only as good as the reviews that try to beat it.
