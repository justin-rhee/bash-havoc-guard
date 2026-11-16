# bash-havoc-guard

[![tests](https://github.com/justin-rhee/bash-havoc-guard/actions/workflows/test.yml/badge.svg)](https://github.com/justin-rhee/bash-havoc-guard/actions/workflows/test.yml) [![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) ![shell](https://img.shields.io/badge/shell-bash-blue.svg) ![needs jq](https://img.shields.io/badge/needs-jq-lightgrey.svg)

Stops a Claude Code agent from printing your secrets, sending data off your machine, or running destructive commands.

```console
$ bash-havoc-guard.sh --explain 'cat ~/.config/gh/hosts.yml'
BLOCKED [secrets]: content access to a credential path: ~/.config/gh/hosts.yml

$ bash-havoc-guard.sh --explain 'rm -rf ../..'
BLOCKED [destruction]: recursive rm through a parent path: ../..

$ bash-havoc-guard.sh --explain 'curl http://localhost:3000/health'
allowed
```

The guard I wrote before this one lasted two commands. One printed my GitHub token, the other published a file to a public web page, and I only found out by telling a second agent to get through it. If you let an agent run shell commands, you have this too, whether or not anything has gone wrong yet.

## Use it if

- you run a Claude Code agent that executes shell commands, especially unattended or in a loop
- you want a cheap guardrail against reading a secret, shipping data out, or something destructive
- you want it in front of an OS sandbox, not instead of one

## Install

It needs `jq`. Copy the script, make it runnable, and register it as a hook:

```console
$ cp src/bash-havoc-guard.sh ~/.claude/hooks/
$ chmod +x ~/.claude/hooks/bash-havoc-guard.sh
```

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [ { "type": "command", "command": "bash ~/.claude/hooks/bash-havoc-guard.sh" } ] }
    ]
  }
}
```

Start a new session for it to take effect, then ask your agent to run `rm -rf ../..` and watch it decline. Before relying on it, run `--explain` on commands you use every day, and adjust the five settings marked `# EDIT` in the script if it blocks one (allowed delete folders first).

## How it works

Claude Code runs it before each command and lets it veto, with three checks:

- reading secrets: blocks dumping a credential file's contents, while still letting you list the folder, check a size or take a fingerprint
- sending things out: blocks a network command unless it points at your own machine or network, leaving ordinary `git` and `gh` alone except the few commands that publish
- destroying things: blocks recursive deletes outside allowed folders, raw disk writes, disk wipes, `git clean` and force pushes

It fails open on input it can't parse, because a guard that jams the session gets ripped out that afternoon. The agent can't talk its way past it: there's no flag to skip the check, so a legitimate blocked command is one you run yourself.

## What it won't do

It won't stop someone determined. An encoded command, one built from pieces at the last second, or a filename hidden in a variable all get past a check that reads commands as text. An OS sandbox is the real answer; this runs in front of one.

It works from shapes it recognizes, so something new gets through, and it only watches shell commands.

It goes too far in two places, on purpose. `rm -rf $(pwd)` is blocked while `rm -rf $DIR` is allowed, because a target computed on the spot is a delete it can never see. And writing a dangerous-looking line into a file still blocks, since telling the two apart means parsing shell rather than reading text. `--explain` names the check that fired; if what it objected to is text inside a document, it's a false alarm, and running it yourself is the intended path.

Windows isn't supported yet.

## How I tested it

- 130 offline cases: `bash tests/test-bash-havoc-guard.sh`
- includes the awkward ones: fingerprinting a secret file, counting matches without printing them, a folder named for tokens that holds none
- most cases exist because something got through once; the story behind each rule is in [docs/ADR.md](docs/ADR.md)

## License

MIT. See [LICENSE](LICENSE). No warranty. Security notes and how to report a problem: [SECURITY.md](SECURITY.md).

<!-- related:start -->
## Related

- [path-fence](https://github.com/justin-rhee/path-fence): refuses credential-shaped file reads before they happen
- [transcript-redactor](https://github.com/justin-rhee/transcript-redactor): keeps credentials out of agent transcripts

Part of a small set of tools I pulled out of my own agent harness. I use them myself and read every issue. More on my [GitHub profile](https://github.com/justin-rhee).
<!-- related:end -->
