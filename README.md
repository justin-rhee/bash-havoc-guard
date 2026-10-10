# bash-havoc-guard

One shell hook for agents that run commands: **block a command that would dump a credential file's contents**, **block network commands pointed anywhere but your own machine or network**, and **block destructive commands such as recursive deletes outside allowed folders, raw disk writes, disk wipes, `git clean` and force pushes**. About 420 lines of shell, roughly half comments explaining why each rule exists, and it needs `jq`.

The guard I had written before it lasted two commands: one printed my GitHub token, the other published a file off my machine to a public web page, and I found out by pointing a second agent at it and telling it to get through. It did, twice, both times with commands I had never thought to watch. If you let an agent run shell commands, you have this too, whether or not anything has gone wrong yet. This hook is what survived that review.

## Use it if

- you run a Claude Code agent that executes shell commands, especially unattended or in a loop
- you want a cheap guardrail against it reading a secret, shipping data off the machine, or running something destructive
- you want it to sit in front of an OS sandbox, not instead of one

## How it works

Claude Code can run a script before each command and let it veto. This is that script: it gets the command as text and either stays quiet or refuses with a reason. Three checks.

- reading secrets: blocks a command that would dump the contents of a credential file, and still lets you list the folder, check the size, or take a fingerprint without ever printing what's inside
- sending things out: blocks a network command unless it's pointed somewhere on your own machine or network, leaving ordinary `git` and `gh` alone except the handful of commands that publish a file or create a new place to publish to
- destroying things: blocks a recursive delete outside the folders you've said are fine, anything that writes straight to a disk, a disk wipe, `git clean`, and a force push

It fails open: feed it something it can't parse and it allows the command, because a guard that jams the session shut the first time it hits an edge case is one you rip out that afternoon, and then you have no guard at all. The agent cannot override it, though; some hooks let the model pass a flag to skip the check, and this one cannot be talked out of anything. If a blocked command was legitimate you run it yourself, because if the agent could skip the check, so could anything that had talked its way into the agent.

```console
$ bash-havoc-guard.sh --explain 'cat ~/.config/gh/hosts.yml'
BLOCKED [secrets]: content access to a credential path: ~/.config/gh/hosts.yml

$ bash-havoc-guard.sh --explain 'rm -rf ../..'
BLOCKED [destruction]: recursive rm through a parent path: ../..

$ bash-havoc-guard.sh --explain 'curl http://localhost:3000/health'
allowed
```

## Install

You need `jq`. Copy the script somewhere it can live, make it runnable, and tell Claude Code to call it before each command:

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

Start a new session for that to take effect. The first refusal you see is your confirmation it's working; if you'd rather not wait, ask your agent to run `rm -rf ../..` and watch it decline.

Run it against commands you actually use first, with nothing installed and nothing changed. If it stops something you need every day, change a setting now rather than finding out mid-task:

```console
$ bash src/bash-havoc-guard.sh --explain 'rm -rf ./dist'
allowed
```

Five settings are marked `# EDIT` in the script: allowed folders for recursive delete, credential files particular to your setup, filename words suggesting a secret, commands that count as reading contents, and addresses that count as local. Each is a list, one item per line, with a comment saying what it's for; the first is the one most people need to change.

## What it won't do

It won't stop someone genuinely trying to get around it. Encode a command, build it from pieces at the last second, hide a filename in a variable, and this reads commands as text so it misses all of that. The real answer to a determined attacker is an operating system sandbox; this runs in front of one, not instead of one.

It works from a list of shapes it recognises, so something genuinely new gets through, and it only watches shell commands. Anything else your agent can do is outside what it sees.

It also goes too far in two places, both on purpose. `rm -rf $(pwd)` is blocked while `rm -rf $DIR` is allowed, because a target computed on the spot is a delete the guard can never see, and an unknown recursive delete is the last thing that should get a pass. And writing a dangerous-looking line into a file still blocks: saving the text `curl https://example.com` into a document trips the network check on a line that never runs. Telling those apart means parsing shell syntax rather than reading text, and ignoring anything that looks like a document is wrong the other way, since you can pipe a document straight into a shell.

When something blocks and you think it shouldn't have, ask it why; it names the check that fired and the exact thing it objected to. If that thing is a word inside a message or a document rather than something the command would touch, it's a false alarm, and running it yourself outside the agent is the intended path:

```console
$ bash-havoc-guard.sh --explain 'cat > notes.md <<EOF
curl https://example.com
EOF'
BLOCKED [egress]: network command without a local-only destination: curl https://example.com
```

## Platforms

macOS and Linux today, Windows on the way.

## How I tested it

The suite runs offline, no accounts, no keys, no network:

```
bash tests/test-bash-havoc-guard.sh
```

130 cases. It hands the hook made-up commands and checks that the safe ones pass and the dangerous ones don't, including the awkward ones: taking a fingerprint of a secret file, counting matches in it without printing them, a folder named for tokens that holds no secrets at all. Most of those cases exist because something got through; the reasoning behind each rule, and the story of what it missed, is in [docs/ADR.md](docs/ADR.md).

## License

MIT. See [LICENSE](LICENSE). No warranty. Security notes and how to report a problem: [SECURITY.md](SECURITY.md).

This little tool is one of a handful I pulled out of my own day-to-day agent setup. I use them all myself, so when something breaks I usually notice fast. If you spot anything off, open an issue. I read every one. More tools on my [GitHub profile](https://github.com/justin-rhee).
