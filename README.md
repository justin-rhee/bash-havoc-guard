# bash-havoc-guard

[![test](https://github.com/justin-rhee/bash-havoc-guard/actions/workflows/test.yml/badge.svg)](https://github.com/justin-rhee/bash-havoc-guard/actions/workflows/test.yml)

The guard I'd written lasted two commands. One printed my GitHub token, the other published a file off my machine to a public web page, and I found out by pointing a second agent at it and telling it to get through. It did, twice, both times with commands I'd never thought to watch. If you let an agent run shell commands, you have this too, whether or not anything has gone wrong yet.

This hook is what survived that review. It reads every shell command your AI agent is about to run and stops the dangerous ones.

## Use it if

You run a Claude Code agent that executes shell commands, especially unattended or in a loop, and you want a cheap guardrail against it reading a secret, shipping data off the machine, or running something destructive. It sits in front of an OS sandbox, not instead of one.

## How it works

Claude Code can run a script before each command and let it veto. This is that script: it gets the command as text and either stays quiet or refuses with a reason. Three checks.

- reading secrets: blocks a command that would dump the contents of a credential file, and still lets you list the folder, check the size, or take a fingerprint without ever printing what's inside
- sending things out: blocks a network command unless it's pointed somewhere on your own machine or network, leaving ordinary `git` and `gh` alone except the handful of commands that publish a file or create a new place to publish to
- destroying things: blocks a recursive delete outside the folders you've said are fine, anything that writes straight to a disk, a disk wipe, `git clean`, and a force push

It fails open: feed it something it can't parse and it allows the command. A guard that jams the session shut the first time it hits an edge case is one you rip out that afternoon, and then you have no guard at all.

The agent can't override it, though. Some hooks let the model pass a flag to skip the check; this one can't be talked out of anything. If a blocked command was legitimate you run it yourself, because if the agent could skip the check, so could anything that had talked its way into the agent.

```console
$ bash-havoc-guard.sh --explain 'cat ~/.config/gh/hosts.yml'
BLOCKED [secrets]: content access to a credential path: ~/.config/gh/hosts.yml

$ bash-havoc-guard.sh --explain 'rm -rf ../..'
BLOCKED [destruction]: recursive rm through a parent path: ../..

$ bash-havoc-guard.sh --explain 'curl http://localhost:3000/health'
allowed
```

It's about 420 lines of shell, roughly half of that comments explaining why each rule exists, and it needs `jq` to read the command it's handed.

## Try it before you install it

Run it against commands you actually use. Nothing gets installed and nothing changes:

```console
$ bash src/bash-havoc-guard.sh --explain 'rm -rf ./dist'
allowed
$ bash src/bash-havoc-guard.sh --explain 'rm -rf ../..'
BLOCKED [destruction]: recursive rm through a parent path: ../..
```

Worth five minutes with your own habits. If it stops something you need every day, change a setting now rather than finding out mid-task.

## Install

You need `jq`.

Copy the script somewhere it can live, make it runnable, and tell Claude Code to call it before each command:

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

Start a new session for that to take effect. The first refusal you see is your confirmation it's working. If you'd rather not wait, ask your agent to run `rm -rf ../..` and watch it decline.

## Make it yours

Five settings are marked `# EDIT` in the script:

- which folders a recursive delete is allowed in
- any credential files particular to your setup
- the words in a filename that suggest it holds a secret
- the commands that count as reading a file's contents
- the addresses that count as local

Each one is a list, one item per line, with a comment saying what it's for. Adding to any of them means adding a line. The one most people need to change is the first, since it defaults to the usual places people keep code and yours might be somewhere else.

## What it won't do

It won't stop someone genuinely trying to get around it. Encode a command, build it from pieces at the last second, hide a filename in a variable, and this reads commands as text so it misses all of that. The real answer to a determined attacker is an operating system sandbox; this runs in front of one, not instead of one

It works from a list of shapes it recognises, so something genuinely new gets through, and it only watches shell commands. Anything else your agent can do is outside what it sees.

It also goes too far in two places, both on purpose. `rm -rf $(pwd)` is blocked while `rm -rf $DIR` is allowed, because a target computed on the spot is a delete the guard can never see, and an unknown recursive delete is the last thing that should get a pass. And writing a dangerous-looking line into a file still blocks: saving the text `curl https://example.com` into a document trips the network check on a line that never runs. Telling those apart means parsing shell syntax rather than reading text, and ignoring anything that looks like a document is wrong the other way, since you can pipe a document straight into a shell.

When something blocks and you think it shouldn't have, ask it why:

```console
$ bash-havoc-guard.sh --explain 'cat > notes.md <<EOF
curl https://example.com
EOF'
BLOCKED [egress]: network command without a local-only destination: curl https://example.com
```

It names the check that fired and the exact thing it objected to. If that thing is a word inside a message or a document rather than something the command would touch, it's a false alarm, and running it yourself outside the agent is the intended path.

## How I tested it

The suite runs offline. No accounts, no keys, no network:

```
bash tests/test-bash-havoc-guard.sh
```

130 cases. It hands the hook made-up commands and checks that the safe ones pass and the dangerous ones don't, including the awkward ones: taking a fingerprint of a secret file, counting matches in it without printing them, a folder named for tokens that holds no secrets at all.

Most of those cases exist because something got through. The reasoning behind each rule, and the story of what it missed, is in [docs/ADR.md](docs/ADR.md).

## License

MIT. See [LICENSE](LICENSE). No warranty. Security notes and how to report a problem: [SECURITY.md](SECURITY.md).

---

One of a set of small tools I've pulled out of a bigger system I run, where agents write the code and plain scripts decide when it's actually done. I keep the final call for myself, and I'd rather a check be annoying than silent. More of them on my [GitHub profile](https://github.com/justin-rhee).
