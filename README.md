# bash-havoc-guard

[![test](https://github.com/justin-rhee/bash-havoc-guard/actions/workflows/test.yml/badge.svg)](https://github.com/justin-rhee/bash-havoc-guard/actions/workflows/test.yml)

An AI agent with shell access is one bad command away from reading your credentials, shipping them off your machine, or deleting the wrong thing. A slip or a poisoned instruction is all it takes.

bash-havoc-guard is a Claude Code hook that sits in front of every shell command your agent runs and blocks three kinds before they execute: reading a secret file, sending data off the machine, and destroying things. It fails open, so a broken guard can never break a session, and there's no agent override, if a blocked command is legitimate you run it yourself. It's about 120 lines of bash, plus `jq` to read the command.

```console
# your agent tries to read your GitHub token. Claude Code runs the hook first,
# handing it the command as JSON on stdin:
$ echo '{"tool_name":"Bash","tool_input":{"command":"cat ~/.config/gh/hosts.yml"}}' \
    | bash-havoc-guard.sh
BLOCKED by havoc guard [secrets]: content access to a credential path: cat ~/.config/gh/hosts.yml
No agent override exists for this lock. If it's legitimate, run it yourself outside the agent.
```

## Use it if

You run a Claude Code agent that executes shell commands, especially unattended or in a loop, and you want a cheap guardrail against it reading a secret, shipping data off the machine, or running something destructive. It sits in front of an OS sandbox, not instead of one.

## What it blocks

Three locks, and it leans toward letting safe things through:

- A command that reads a credential file with something like `cat`, `grep`, or `base64`. Safe inspection (`ls`, `wc`, `file`, `shasum`, a counting `grep`) stays open, so you can still fingerprint a file without dumping it.
- A network command (`curl`, `wget`, `nc`, `ssh`, `scp`) unless it points at a local address. Normal `git` and `gh` stay open, except the `gh` subcommands that ship data or create and expose a remote.
- A destructive command: recursive `rm` outside a set of safe folders, a raw write to a disk device, a disk wipe (`diskutil`, `mkfs`), or a `git push --force`.

## Install

It's a standard Claude Code PreToolUse hook. Point one at the script in your settings:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [ { "type": "command", "command": "bash /path/to/bash-havoc-guard.sh" } ] }
    ]
  }
}
```

## Configure

Five settings in the script are marked `# EDIT`: the folders where recursive `rm` is allowed, extra credential paths for your setup, the words that make a filename look like a credential store, the commands that count as reading a file's contents, and the local addresses that count as safe destinations. Each one is a list where every entry sits on its own commented line, so adding to one means adding a line rather than editing a long pattern by hand. The defaults are sensible; adjust them for your machine.

## What it won't do

- It won't stop a determined attacker. It's porous against deliberate obfuscation (`base64`, `eval`, hiding a path in a variable), and it doesn't resolve `..` in a path. The real wall for that is an OS-level sandbox; this rides in front of one, not instead of it.
- It's a blocklist, not an allowlist. It stops the dangerous shapes it knows about, and a novel one can get through.
- It only guards `Bash`. Any other tools your agent has are out of scope.

It also errs the other way in two places, and both are deliberate. Naming a dangerous command is otherwise fine as of v1.1.0: `git commit -m "anchor mkfs to command position"` and `echo "run diskutil eraseDisk"` both pass, while the same binaries in command position, including behind `sudo` or `xargs`, still block. What's left over-blocks:

- `rm -rf $(pwd)` is blocked, `rm -rf $DIR` is allowed. A command substitution takes the target away entirely, so the guard has nothing left to judge, and an unknowable recursive delete is the last thing that should fall through to allow. A variable still leaves an operand, so it stays in the variable-indirection tier from the first bullet above, which is an OS sandbox's job rather than this one's.
- A heredoc body line that begins with a dangerous word is blocked, even though nothing on that line runs. Writing `curl https://example.com` into a file with `cat > notes.md <<EOF` trips the network lock on a line of a document. Telling that apart from a real command means parsing heredocs, and this reads a command string. Skipping heredoc bodies wholesale would be wrong in the other direction, since a shell can be fed from one (`bash <<EOF`).

To tell an over-block from a real catch, run the command through `--explain`:

```console
$ bash-havoc-guard.sh --explain 'cat > notes.md <<EOF
curl https://example.com
EOF'
BLOCKED [egress]: network command without a local-only destination: curl https://example.com
```

It names the lock and the operand it objected to. If that operand is a word inside a message or a document rather than something the command would act on, it's an over-block. There's still no override flag, by design, so run it yourself outside the agent.

## How I tested it

You can run the test suite offline, no accounts or keys needed:

```
bash tests/test-bash-havoc-guard.sh    # 24 checks
```

It feeds the hook fake commands and checks that the safe ones pass (including the tricky ones, like a `shasum` fingerprint or a counting `grep` on a secret file) and the dangerous ones get blocked, across all three locks. The reasoning behind each is in [docs/ADR.md](docs/ADR.md).

## License

MIT. See [LICENSE](LICENSE). No warranty. Security notes and how to report a problem: [SECURITY.md](SECURITY.md).

---

One of a set of small tools I've pulled out of a bigger system I run, where agents write the code and plain scripts decide when it's actually done. They all share one rule: the machine suggests, a person decides, and nothing quietly goes wrong behind your back. More of them on my [GitHub profile](https://github.com/justin-rhee).
