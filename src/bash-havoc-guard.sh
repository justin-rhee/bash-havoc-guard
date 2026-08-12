#!/usr/bin/env bash
# bash-havoc-guard.sh - a Claude Code PreToolUse hook that guards an agent's shell.
#
# Three locks, in plain terms:
#   1. SECRETS      block a command that reads a credential file with a dumper like
#                   cat / grep / base64. Safe inspection (ls, wc, file, shasum, a
#                   counting grep) stays open, and so do source and doc files that
#                   merely have "token" or "secret" in the name.
#   2. EGRESS       block a network command (curl / wget / nc / ssh / scp / ...)
#                   unless it targets a local address. git / gh / npm stay open,
#                   except the gh subcommands that ship data or create or expose a
#                   remote.
#   3. DESTRUCTION  block recursive rm outside safe folders, rm that escapes the
#                   working directory, rm whose target cannot be resolved, recursive
#                   chmod of / or $HOME, raw-device dd, disk wipes, git clean, and
#                   git force-push.
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
# Try it without installing anything:
#   bash src/bash-havoc-guard.sh --explain 'cat ~/.ssh/id_rsa'
#
# Three settings below are marked `# EDIT`: your safe rm roots, extra credential
# paths, and your local network ranges. The defaults are sensible.

set -u

# ---- input ----------------------------------------------------------------
# --explain runs one command through the locks and prints the verdict. It exists so
# you can check your own commands before wiring the hook into settings.json.
EXPLAIN=0
if [ "${1:-}" = "--explain" ]; then
  EXPLAIN=1
  CMD="${2:-}"
else
  command -v jq >/dev/null 2>&1 || exit 0
  PAYLOAD=$(cat 2>/dev/null) || exit 0
  [ -n "$PAYLOAD" ] || exit 0
  TOOL=$(jq -r '.tool_name // ""' <<<"$PAYLOAD" 2>/dev/null) || exit 0
  [ "$TOOL" = "Bash" ] || exit 0
  CMD=$(jq -r '.tool_input.command // ""' <<<"$PAYLOAD" 2>/dev/null)
fi
if [ -z "$CMD" ]; then
  [ "$EXPLAIN" -eq 1 ] && echo "allowed: empty command"
  exit 0
fi

deny() {
  if [ "$EXPLAIN" -eq 1 ]; then
    echo "BLOCKED [$1]: $2"
    exit 2
  fi
  {
    echo "BLOCKED by havoc guard [$1]: $2"
    echo "No agent override exists for this lock. If it's legitimate, run it yourself outside the agent."
  } >&2
  exit 2
}

# `${HOME}` and `$HOME` are the same path; normalising here keeps every downstream
# pattern simple and lets the segment splitter treat braces as syntax.
CMD=$(sed -E 's/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/$\1/g' <<<"$CMD")

# A command substitution, a subshell, or a backtick starts a NEW command, so each has
# to be judged on its own. Splitting only on |;& let `X=$(curl https://evil)` and
# `(rm -rf ~/Documents)` past the command-position checks below.
# NOTE: braces are NOT split on. `{ cmd; }` grouping always carries a `;` or `&`,
# which already splits, whereas a JSON body (`curl -d '{"a":1}' https://x`) would be
# shattered - orphaning the URL into a segment with no command in front of it.
split_segments() { sed -E 's/\$\(/\n/g; s/[`()]/\n/g' <<<"$1" | tr '|;&' '\n'; }

# whitespace-separated operands, quotes stripped. Paths containing spaces are a
# known gap: a quoted "my file.txt" splits into two tokens.
tokens() { tr ' \t' '\n' <<<"$1" | sed -E 's/^["'\'']+//; s/["'\'']+$//' | grep -v '^$'; }

# Peel launchers off the front of a segment so the real command lands in first position.
# A dangerous binary hiding behind sudo/xargs/eval is still that binary; used by BOTH the
# egress and destruction locks, which is why it lives here and not inline.
strip_launchers() {
  sed -E 's/^[[:space:]]*//;
          s/^((sudo|env|time|timeout|nohup|command|exec|xargs|eval|stdbuf|nice|ionice)([[:space:]]+(-[^[:space:]]+|[0-9.]+[smhd]?))*[[:space:]]+)*//;
          s/^((bash|sh|zsh|ksh)[[:space:]]+-c[[:space:]]+)//;
          s/^["'\'']+//' <<<"$1"
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
# CRED_HARD is a real credential store and always wins. CRED_WORD is a heuristic on
# the words token / secret / apikey in a filename, and it used to block
# `cat src/tokens.json` and `cat docs/design-tokens.md` - design-system files, not
# credentials. A guard that blocks a designer's own token file every morning gets
# uninstalled by lunch, so CRED_WORD now yields on source and doc files.
# EDIT: add any credential paths specific to your setup to CRED_HARD.
CRED_HARD='(^|[[:space:]"'\''/=@])\.(ssh|aws|kube|netrc|pgpass)(/|\b)|\.config/(gcloud|rclone|gh|anthropic)\b|Library/Keychains|id_rsa|id_ed25519|\.credentials\.json|\.(pem|key|p12|pfx)([[:space:]]|$|["'\''])|(^|[[:space:]"'\''/=@])\.env(\.[A-Za-z0-9_.-]+)?($|[[:space:]"'\''])'
CRED_WORD='[^[:space:]"'\'']*/[A-Za-z0-9_.-]*(token|secret|apikey|api_key)[A-Za-z0-9_.-]*([[:space:]]|$|["'\''])|(^|[[:space:]"'\''=@])[.~][A-Za-z0-9_.~-]*(token|secret|apikey|api_key)[A-Za-z0-9_.-]*([[:space:]]|$|["'\''])|[A-Za-z0-9_-]*(token|secret|apikey|api_key)[A-Za-z0-9_-]*\.[A-Za-z0-9]+([[:space:]]|$|["'\''])'
CRED="$CRED_HARD|$CRED_WORD"
# a source or doc file is not a credential store, whatever it is called
BENIGN_EXT='\.(md|markdown|mdx|rst|adoc|ts|tsx|js|jsx|mjs|cjs|py|rb|go|rs|java|kt|swift|c|h|cc|cpp|hpp|cs|php|css|scss|sass|less|styl|html|vue|svelte|astro)$'
# Ambiguous extensions yield ONLY under an obvious source directory. `.txt`, `.sh`
# and `.sql` are the shapes a naive credential file actually takes - api_token.txt
# and secrets.sh are stores, while docs/tokens.txt and scripts/tokens.sh are not.
BENIGN_SRC='(^|/)(src|source|docs?|app|apps|components?|styles?|lib|libs|tests?|specs?|scripts?|examples?|packages|design|stories|fixtures)/[^[:space:]]*\.(json|ya?ml|toml|xml|csv|txt|sql|sh|bash|zsh|lock)$'

# Case-insensitive: a store called API_KEY or Secret.conf is a store. This was only
# safe to tighten once CRED_WORD had the benign tier under it - matching TOKEN as
# well as token would otherwise have blocked every TokenBadge.tsx in the repo.
is_cred_operand() {
  local op=" $1 "
  grep -Eqi "$CRED_HARD" <<<"$op" && return 0
  if grep -Eqi "$CRED_WORD" <<<"$op"; then
    # a doc or source EXTENSION is benign wherever it lives
    grep -Eqi "$BENIGN_EXT" <<<"$1" && return 1
    # a source DIRECTORY only counts on a repo-relative path. `app/` and `src/` appear
    # inside absolute system paths too, and /opt/app/apikey.txt is a deployment
    # credential, not a fixture - matching the directory anywhere let it through.
    case "$1" in
      /*|~*|\$HOME*) : ;;
      *) grep -Eqi "$BENIGN_SRC" <<<"$1" && return 1 ;;
    esac
    return 0
  fi
  return 1
}

# gh is authenticated, so `gh gist create <secret>` is a one-command exfil primitive
# that no cred-path filter would see; it is handled in the EGRESS lock below.
DUMPERS='\b(cat|head|tail|less|more|strings|xxd|od|hexdump|base64|openssl|cut|awk|sed|sort|rev|tac|nl|paste|column|grep|egrep|fgrep|rg|ag|ack|cp|mv|ditto|tar|zip|gzip|bzip2|rsync|scp|dd|install|tee|source|gh|python[0-9.]*|ruby|perl|node|php)\b|(^|[;&|][[:space:]]*)\.[[:space:]]'
while IFS= read -r seg; do
  [ -n "$seg" ] || continue
  grep -Eqi "$CRED" <<<"$seg" || continue
  # decide per operand, so one benign token file cannot be blamed on the segment
  hit=""; matched=0
  while IFS= read -r op; do
    grep -Eqi "$CRED" <<<" $op " || continue
    matched=1
    if is_cred_operand "$op"; then hit="$op"; break; fi
  done < <(tokens "$seg")
  # every cred-shaped operand turned out to be a source or doc file
  [ "$matched" -eq 1 ] && [ -z "$hit" ] && continue
  # drop sanctioned count/quiet greps (grep/rg with a -c or -q flag) before dumper
  # matching; anchored on [[:space:]], not \b, because BSD sed has no \b
  segx=$(sed -E 's/(^|[[:space:]])(grep|egrep|fgrep|rg)[[:space:]]+(-[a-zA-Z]+[[:space:]]+)*-[a-zA-Z]*[cq][a-zA-Z]*([[:space:]]|$)/ /g' <<<"$seg")
  if grep -Eq "$DUMPERS" <<<"$segx"; then
    deny "secrets" "content access to a credential path: ${hit:-${seg:0:120}}"
  fi
done < <(split_segments "$STRIPPED")

# ---- 2. EGRESS LOCK -------------------------------------------------------
# EDIT: local destinations that are allowed. Default covers localhost, the loopback
# addresses, the Tailscale range (100.64/10), *.local, and *.ts.net. Add your own
# RFC1918 ranges here if your agent talks to a LAN service.
# Anchored to the WHOLE host, and to a dot boundary for the suffixes. An unanchored
# allow-list is the same bug as the `curl -A localhost` incident one layer down:
# localhost.evil.example contains "localhost" and is not local.
LOCALOK='^(localhost|127\.0\.0\.1|::1|0\.0\.0\.0)$|(^|\.)(ts\.net|local)$|^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}$'

# A network binary only counts in COMMAND position. Matching it anywhere blocked
# `grep -rn curl scripts/` and `echo 'RUN curl https://x' > Dockerfile`, where the
# word is an argument and nothing leaves the machine.
while IFS= read -r seg; do
  [ -n "$seg" ] || continue
  # a network binary hiding behind a launcher is still a network binary
  s=$(strip_launchers "$seg")
  first=${s%%[[:space:]]*}
  first=${first##*/}

  # gh is authenticated: its publish / write subcommands ship data. Plain `gh api`
  # GETs and `gh pr` / `gh --version` stay open; anything that sends data does not.
  if [ "$first" = "gh" ]; then
    if grep -Eq '^gh[[:space:]]+gist\b|^gh[[:space:]]+release[[:space:]]+upload\b|^gh[[:space:]]+api\b.*(-X|--method)[[:space:]]*(POST|PUT|PATCH|DELETE)|^gh[[:space:]]+api\b.*(-f|--field|--input)\b' <<<"$s"; then
      deny "egress" "gh publish/write subcommand (can exfiltrate): ${s:0:120}"
    fi
    # git push stays open on the assumption of a known remote, but these create or
    # flip a remote, so locally-committed secrets could ship to a sink that did not
    # exist when this guard was written. `gh repo delete` is the same family's
    # irreversible destruction primitive. All of these are human-only.
    if grep -Eq '^gh[[:space:]]+repo[[:space:]]+(create|fork|delete)\b|^gh[[:space:]]+repo[[:space:]]+edit\b[^|;&]*--visibility' <<<"$s"; then
      deny "egress" "gh repo create/expose/delete (a new-remote exfil path): ${s:0:120}"
    fi
    continue
  fi

  case "$first" in
    curl|wget|nc|ncat|netcat|socat|scp|sftp|telnet|rsync|ssh|ftp) ;;
    openssl) grep -Eq '^openssl[[:space:]]+s_client\b' <<<"$s" || continue ;;
    *) continue ;;
  esac

  rest=$(sed -E 's/^[^[:space:]]+[[:space:]]*//' <<<"$s")
  ops=$(tokens "$rest" | grep -Ev '^-' || true)
  # no operand means no destination: `curl --help`, `wget --version`, bare `rsync`
  [ -n "$ops" ] || continue
  # rsync and scp are local file copies unless an operand carries a host:path
  case "$first" in
    rsync|scp) grep -Eq '(^|[^/[:alnum:]])[A-Za-z0-9_.-]+:' <<<"$ops" || continue ;;
  esac

  # Anchor the local-destination test to the URL HOST, not the whole command.
  # Matching the allow-list anywhere let `curl -A localhost https://evil.example/...`
  # through: a user-agent string satisfied a check that was meant to describe where
  # the data goes.
  bad=0
  HOSTS=$(grep -oE 'https?://[^[:space:]"'\''/]+' <<<"$s" | sed -E 's|https?://||; s|.*@||; s|:[0-9]+$||')
  if [ -n "$HOSTS" ]; then
    while IFS= read -r h; do
      [ -n "$h" ] || continue
      grep -Eq "$LOCALOK" <<<"$h" || bad=1
    done <<<"$HOSTS"
  else
    # no URL present (e.g. `nc host port`): the destination is one of the operands,
    # so test each one as a host rather than substring-matching the whole segment
    bad=1
    while IFS= read -r o; do
      o=$(sed -E 's|^[^/]*@||; s|:[0-9]+$||; s|:.*$||' <<<"$o")
      grep -Eq "$LOCALOK" <<<"$o" && { bad=0; break; }
    done <<<"$ops"
  fi
  [ "$bad" -eq 1 ] && deny "egress" "network command without a local-only destination: ${s:0:120}"
done < <(split_segments "$CMD")

# ---- 3. DESTRUCTION LOCK --------------------------------------------------
# EDIT: recursive rm is allowed only BENEATH these roots - this is the one setting
# most people have to change. Point it at wherever your repos actually live, or the
# first `rm -rf dist` of the day gets blocked.
SAFE_RM_ROOTS=(
  "$HOME/projects" "$HOME/code" "$HOME/dev" "$HOME/src" "$HOME/repos"
  "$HOME/work" "$HOME/Developer" "$HOME/Documents/GitHub"
  "/tmp" "/private/tmp" "/private/var/folders" "$HOME/.Trash"
)

expand_home() { sed -E "s|^\\\$\{HOME\}|$HOME|; s|^\\\$HOME|$HOME|; s|^~|$HOME|" <<<"$1"; }

# The old extractor only looked at operands starting with / ~ or $HOME, so the most
# likely real-world havoc walked straight through: an agent runs with its cwd inside
# your repo, and `rm -rf ../..` or `rm -rf *` needs no absolute path at all.
# A `cd` earlier in the command is carried forward, because `cd ~/Documents && rm -rf
# notes` is one command and has to be judged as one.
CWD_HINT=""
while IFS= read -r seg; do
  [ -n "$seg" ] || continue
  if grep -Eq '^[[:space:]]*cd[[:space:]]' <<<"$seg"; then
    d=$(tokens "$(sed -E 's/^[[:space:]]*cd[[:space:]]+//' <<<"$seg")" | grep -Ev '^-' | head -1)
    d=$(expand_home "${d:-}")
    case "$d" in /*) CWD_HINT="$d" ;; esac
  fi
  grep -Eq '(^|[[:space:]])(sudo[[:space:]]+)?rm([[:space:]]|$)' <<<"$seg" || continue
  grep -Eq '[[:space:]]-[a-zA-Z-]*r' <<<"$seg" || continue
  seen_rm=0
  operands=0
  while IFS= read -r tok; do
    if [ "$seen_rm" -eq 0 ]; then
      [ "${tok##*/}" = "rm" ] && seen_rm=1
      continue
    fi
    case "$tok" in -*) continue ;; esac
    operands=$((operands + 1))
    t=$(expand_home "$tok")
    case "$t" in
      /|"$HOME"|"$HOME"/|'*'|'./*'|'/*'|"$HOME/*")
        deny "destruction" "recursive rm of a catastrophic target: $tok" ;;
      .|..|./|../)
        deny "destruction" "recursive rm of the working directory or its parent: $tok" ;;
      *../*|*/..)
        deny "destruction" "recursive rm through a parent path: $tok" ;;
    esac
    # a relative target is judged against an explicit cd if the command gave us one;
    # without one we cannot know the agent's cwd, and that is a stated ceiling
    case "$t" in /*) ;; *) [ -n "$CWD_HINT" ] && t="$CWD_HINT/$t" || continue ;; esac
    safe=0
    for root in "${SAFE_RM_ROOTS[@]}"; do
      case "$t" in "$root"/?*) safe=1; break ;; esac
    done
    [ "$safe" -eq 0 ] && deny "destruction" "recursive rm outside allowed roots (offending target: $t)"
  done < <(tokens "$seg")
  # A recursive rm whose segment carries NO operand had its target taken away by the
  # splitter: `rm -rf $(pwd)`, `rm -rf `pwd``, or `... | xargs rm -rf`. The target is
  # real, it just is not knowable here, and an unknowable recursive delete is exactly
  # the case that must not fall through to allow. Variable indirection (`rm -rf $DIR`)
  # still leaves an operand and stays a stated gap - an OS sandbox's tier, not this one.
  [ "$seen_rm" -eq 1 ] && [ "$operands" -eq 0 ] &&
    deny "destruction" "recursive rm with an unresolvable target (command substitution or piped input)"
done < <(split_segments "$STRIPPED")

# The remaining destruction checks match in COMMAND POSITION, the same way the network
# binaries do. Matching them anywhere in the command string meant that naming one was
# treated as running one: `git commit -m "anchor mkfs to command position"` was blocked by
# the mkfs rule, and `echo "run diskutil eraseDisk"` by the diskutil rule. A guard that
# refuses to let you WRITE ABOUT a dangerous command trains you to work around it, which
# costs more than the rule earns.
while IFS= read -r seg; do
  [ -n "$seg" ] || continue
  s=$(strip_launchers "$seg")
  first=${s%%[[:space:]]*}
  first=${first##*/}
  case "$first" in
    dd)
      grep -Eq '[[:space:]]of=/dev/' <<<"$s" && deny "destruction" "raw device write via dd" ;;
    diskutil)
      grep -Eq '\b(erase[A-Za-z]*|reformat|partitionDisk|zeroDisk)\b' <<<"$s" &&
        deny "destruction" "diskutil erase-class command" ;;
    mkfs|mkfs.*)
      deny "destruction" "mkfs" ;;
    chmod)
      # chmod -R on / or $HOME is not recoverable: sudo and sshd both refuse to run
      # against world-writable paths. Same shape as the rm rule, so it reuses its targets.
      if grep -Eq '[[:space:]]-[a-zA-Z]*R' <<<"$s"; then
        while IFS= read -r tok; do
          case "$tok" in -*) continue ;; esac
          case "$(expand_home "$tok")" in
            /|"$HOME"|"$HOME"/|'/*'|"$HOME/*")
              deny "destruction" "recursive chmod of / or \$HOME: $tok" ;;
          esac
        done < <(tokens "$s")
      fi ;;
    git)
      # Command position is not enough for git: the dangerous part is the SUBCOMMAND, and
      # a message can carry another subcommand's name. `git commit -m "block git clean
      # -xfd"` matched the clean rule until the subcommand was isolated. Strip git's own
      # global options first, so `git -C path push --force` still resolves to push.
      sub=$(sed -E 's/^git[[:space:]]+//;
                    s/^((-[cC][[:space:]]+[^[:space:]]+|--(git-dir|work-tree|namespace)=[^[:space:]]+|--(no-pager|bare|paginate|literal-pathspecs))[[:space:]]+)*//' <<<"$s")
      subcmd=${sub%%[[:space:]]*}
      case "$subcmd" in
        push)
          grep -Eq '[[:space:]](-f|--force(-with-lease)?)([[:space:]]|$)' <<<"$sub" &&
            deny "destruction" "git force-push" ;;
        clean)
          # git clean discards untracked files with no reflog to recover them, same family as rm
          grep -Eq '[[:space:]](-[a-zA-Z]*f[a-zA-Z]*|--force)([[:space:]]|$)' <<<"$sub" &&
            deny "destruction" "git clean (irreversibly discards untracked files)" ;;
      esac ;;
  esac
done < <(split_segments "$STRIPPED")

[ "$EXPLAIN" -eq 1 ] && echo "allowed"
exit 0
