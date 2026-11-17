"""What a tool call does, read from its structure instead of its spelling (2026-11-17, docs/actions.md).

The rules used to search a shell command's text: ``r''m -rf x`` or ``rm -r \\<newline> -f x`` slipped
through, and ``echo 'never run rm -rf /'`` or a commit message asked for approval. This module reads a
limited POSIX shell subset into words and simple commands (quotes, escapes, line continuations, ``;``
``&&`` ``||`` ``|`` newlines, redirects, quoted heredocs, a few wrappers) and writes what it found as
labels. The rules decide; a rule tagged ``normalized-by:sga_act`` reads these labels instead of the raw
text only when the whole call was understood (``sga_act_parse=ok``). Anything else keeps the raw-text
rules as the backstop (detect/engine.py).

Labels (the sensor writes them; the same names arriving with an event are dropped, core._OWN_LABELS):

- ``sga_act_parse``: ``ok`` (every command was read and is either modelled or known to treat its arguments
  as data), ``partial`` (read, but some command is outside the model: ``npm``, a script, inline code),
  ``unsupported`` (the structure itself could not be read: command substitution, a command name in a
  variable, ``eval``, ``case``, a function definition, an unterminated quote, PowerShell).
- ``sga_act_unknown``: why it is not ``ok`` (``unmodelled:npm``, ``script:./x.sh``, ``dynamic-command``…).
- ``sga_act_ops``: ``delete``, ``write``, ``exec``, ``read`` found in the modelled part.
- ``sga_act_destroy``: the destructive kinds found (``KINDS``), comma separated.
- ``sga_act_targets``: what those act on, as written (``$DIR`` stays ``$DIR``: not resolved).

Positive findings are real even when the parse is not ``ok`` (``npm test && rm -rf dist`` still reports
the delete). Only the absence of a finding needs ``ok`` to mean anything.

Not a general shell parser, and not claimed to be one: no variable values, no aliases or functions
from the person's shell profile, no ``$(...)``, no script contents, no other languages.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from typing import Any

from ..schema import AgentEvent, EventKind
from . import tools

PARSER = "sh-subset/1"
LABELS = ("sga_act_parse", "sga_act_unknown", "sga_act_ops", "sga_act_destroy", "sga_act_targets")
MAX_CHARS = 20_000
MAX_DEPTH = 3
TARGETS_MAX = 500

# What rules/tool_misuse.yaml calls destructive, as kinds (the raw regex's branches, one by one).
KINDS = (
    "rm-recursive-force",  # rm with -r and -f
    "rm-recursive",  # rm -r without -f: asks too (user decision 2026-11-17; non-interactive, it deletes)
    "find-delete",
    "find-exec-rm",
    "shred-file",
    "git-clean-force",
    "git-reset-hard",
    "git-checkout-all",
    "git-restore-all",
    "git-push-force",
    "mkfs-format",
    "dd-raw-write",
    "chmod-777-root",
)

SHELL_TOOLS = tools.SHELL - {"PowerShell"}
COMMAND_KEYS = ("command", "cmd", "script")

# Commands whose arguments are data: they never run or delete what they are given.
SAFE = frozenset({
    "echo", "printf", "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag", "wc",
    "sort", "uniq", "cut", "tr", "ls", "pwd", "cd", "pushd", "popd", "true", "false", ":", "test", "[",
    "[[", "]]", "which", "type", "whoami", "id", "date", "printenv", "basename", "dirname", "realpath",
    "readlink", "stat", "file", "du", "df", "diff", "cmp", "jq", "yq", "mkdir", "touch", "cp", "mv", "ln",
    "tee", "column", "nl", "fold", "comm", "join", "paste", "base64", "sha256sum", "shasum", "md5sum",
    "export", "unset", "set", "shopt", "local", "read", "sleep", "wait", "exit", "return", "uname",
    "hostname", "tree", "open", "code",
})  # fmt: skip
GIT_SAFE = frozenset({
    "status", "log", "show", "diff", "add", "commit", "grep", "branch", "fetch", "pull", "remote",
    "rev-parse", "ls-files", "blame", "tag", "switch", "merge", "rebase", "cherry-pick", "init", "clone",
    "describe", "shortlog", "reflog", "mv", "rm", "stash", "config", "worktree", "submodule", "apply",
    "format-patch", "am", "bisect", "notes", "ls-remote", "cat-file", "rev-list", "for-each-ref",
})  # fmt: skip
# Words that open or close a compound command: the commands inside are read like any other.
TRANSPARENT = frozenset({"if", "then", "elif", "else", "fi", "while", "until", "do", "done", "!", "{", "}"})
UNSUPPORTED_KEYWORDS = frozenset({"case", "esac", "select", "function", "coproc"})
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
INTERPRETERS = frozenset({
    "python", "python2", "python3", "node", "perl", "ruby", "php", "deno", "bun", "osascript", "pwsh",
    "powershell", "powershell.exe", "pwsh.exe", "cmd", "cmd.exe", "lua", "tclsh", "Rscript", "awk", "gawk",
    "sed",  # GNU sed's e command runs a shell
})  # fmt: skip
_SUDO_ARGS = {"-u", "-g", "-h", "-p", "-C", "-U", "-r", "-t", "-D", "-R", "-T"}
_PY_VERSIONED = re.compile(r"^python\d+(?:\.\d+)?$")
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class Unsupported(Exception):
    """Part of the command is outside the supported subset; the reason is recorded."""


@dataclass
class Word:
    text: str  # quotes removed, escapes applied; an expansion stays as written ($DIR)
    dynamic: bool = False  # holds a parameter expansion
    glob: bool = False  # unquoted * ? [ or a brace expansion
    quoted: bool = False


@dataclass
class Op:
    op: str
    body: str | None = None  # a heredoc's text
    body_literal: bool = True  # quoted delimiter: the body is not expanded


@dataclass
class Command:
    words: list[Word] = field(default_factory=list)
    redirects: list[tuple[Op, Word | None]] = field(default_factory=list)
    piped: bool = False  # stdin comes from the previous command


# ── tokenizer ───────────────────────────────────────────────────────────────

_OPS = ("&&", "||", ";;", "|&", ">>", ">&", "<&", "&>>", "&>", ">|", "<>", "<<<", "<<-", "<<", ";", "&", "|",
        "(", ")", "<", ">")  # fmt: skip


def tokenize(text: str) -> list[Word | Op]:
    if len(text) > MAX_CHARS:
        raise Unsupported("too-long")
    out: list[Word | Op] = []
    buf: list[str] = []
    started = False
    dyn = glob = quoted = False
    pending: list[Op] = []  # heredocs whose body starts after the next newline
    i, n = 0, len(text)

    def flush() -> None:
        nonlocal buf, started, dyn, glob, quoted
        if started:
            out.append(Word("".join(buf), dyn, glob, quoted))
        buf, started, dyn, glob, quoted = [], False, False, False, False

    def expansion(j: int) -> int:
        """A parameter expansion at text[j] == '$': marks the word dynamic, returns where it ends."""
        nonlocal dyn, started
        nxt = text[j + 1 : j + 2]
        if nxt == "(":
            raise Unsupported("command-substitution")
        if nxt == "'":
            raise Unsupported("ansi-c-quote")
        if nxt == "{":
            end = text.find("}", j + 2)
            if end < 0:
                raise Unsupported("unterminated-expansion")
            buf.append(text[j : end + 1])
            dyn = started = True
            return end + 1
        if nxt and (nxt.isdigit() or nxt in "@*#?$!-"):
            buf.append(text[j : j + 2])
            dyn = started = True
            return j + 2
        if m := _NAME.match(text, j + 1):
            buf.append(text[j : m.end()])
            dyn = started = True
            return m.end()
        buf.append("$")
        started = True
        return j + 1

    while i < n:
        c = text[i]
        if c == "\\":
            if text[i + 1 : i + 2] == "\n":
                i += 2  # line continuation
                continue
            if i + 1 < n:
                buf.append(text[i + 1])
                started = quoted = True
                i += 2
                continue
            buf.append("\\")
            started = True
            i += 1
        elif c == "'":
            end = text.find("'", i + 1)
            if end < 0:
                raise Unsupported("unterminated-quote")
            buf.append(text[i + 1 : end])
            started = quoted = True
            i = end + 1
        elif c == '"':
            started = quoted = True
            i += 1
            while True:
                if i >= n:
                    raise Unsupported("unterminated-quote")
                d = text[i]
                if d == '"':
                    i += 1
                    break
                if d == "\\" and text[i + 1 : i + 2] in ('"', "\\", "$", "`", "\n"):
                    if text[i + 1] != "\n":
                        buf.append(text[i + 1])
                    i += 2
                elif d == "`":
                    raise Unsupported("command-substitution")
                elif d == "$":
                    i = expansion(i)
                else:
                    buf.append(d)
                    i += 1
        elif c == "`":
            raise Unsupported("command-substitution")
        elif c == "$":
            i = expansion(i)
        elif c in " \t\r":
            flush()
            i += 1
        elif c == "\n":
            flush()
            out.append(Op("\n"))
            i += 1
            for doc in pending:  # heredoc bodies, in order
                i = _heredoc_body(text, i, doc)
            pending = []
        elif c == "#" and not started:
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif c in ";&|()<>":
            if c in "<>" and started and not quoted and buf and "".join(buf).isdigit():
                buf, started = [], False  # a file descriptor number (2>, 1>&2): part of the redirect
            flush()
            if text.startswith(("<(", ">("), i):
                raise Unsupported("process-substitution")
            op = next(o for o in _OPS if text.startswith(o, i))
            if op == ";;":
                raise Unsupported("control-flow:case")
            if op == "(" and out and isinstance(out[-1], Word) and text[i + 1 : i + 2] == ")":
                raise Unsupported("function-definition")
            i += len(op)
            tok = Op(op)
            out.append(tok)
            if op in ("<<", "<<-"):
                # the delimiter word follows; read it here so its quoting is known
                while i < n and text[i] in " \t":
                    i += 1
                m = re.match(r"(['\"]?)([^\s'\";&|<>()]+)\1", text[i:])
                if not m:
                    raise Unsupported("heredoc")
                tok.body = m.group(2)  # the delimiter until the body is read
                tok.body_literal = bool(m.group(1))
                i += m.end()
                pending.append(tok)
        else:
            if c in "*?[{":
                glob = True  # a pattern or a brace expansion: what it names is decided by the shell
            buf.append(c)
            started = True
            i += 1
    flush()
    if pending:
        raise Unsupported("heredoc")
    return out


def _heredoc_body(text: str, i: int, doc: Op) -> int:
    delim = doc.body or ""
    lines: list[str] = []
    while i <= len(text):
        end = text.find("\n", i)
        line = text[i:] if end < 0 else text[i:end]
        nxt = len(text) + 1 if end < 0 else end + 1
        if (line.lstrip("\t") if doc.op == "<<-" else line) == delim:
            doc.body = "\n".join(lines)
            return nxt
        lines.append(line)
        if end < 0:
            break
        i = nxt
    raise Unsupported("heredoc")


def commands(tokens: list[Word | Op]) -> list[Command]:
    out: list[Command] = []
    cur = Command()
    pipe_next = False
    k = 0
    while k < len(tokens):
        t = tokens[k]
        if isinstance(t, Word):
            cur.words.append(t)
        elif t.op in ("<", ">", ">>", ">|", "&>", "&>>", "<>", ">&", "<&", "<<<"):
            target = tokens[k + 1] if k + 1 < len(tokens) and isinstance(tokens[k + 1], Word) else None
            if target is None:
                raise Unsupported("redirect")
            cur.redirects.append((t, target))  # type: ignore[arg-type]
            k += 1
        elif t.op in ("<<", "<<-"):
            cur.redirects.append((t, None))
        else:  # a separator: ; & && || | |& ( ) newline
            if cur.words or cur.redirects:
                cur.piped = pipe_next
                out.append(cur)
            pipe_next = t.op in ("|", "|&")
            cur = Command()
        k += 1
    if cur.words or cur.redirects:
        cur.piped = pipe_next
        out.append(cur)
    return out


# ── analysis ────────────────────────────────────────────────────────────────


@dataclass
class Facts:
    parse: str = "ok"  # ok | partial | unsupported
    unknown: list[str] = field(default_factory=list)
    ops: set[str] = field(default_factory=set)
    destroy: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)

    def gap(self, reason: str, *, unsupported: bool = False) -> None:
        if reason not in self.unknown:
            self.unknown.append(reason)
        if unsupported:
            self.parse = "unsupported"
        elif self.parse == "ok":
            self.parse = "partial"

    def found(self, kind: str, targets: list[Word] | None = None) -> None:
        if kind not in self.destroy:
            self.destroy.append(kind)
        self.add_targets(targets or [])

    def add_targets(self, targets: list[Word]) -> None:
        for t in targets:
            if t.text not in self.targets:
                self.targets.append(t.text)

    def labels(self) -> dict[str, str]:
        out = {"sga_act_parse": self.parse}
        if self.unknown:
            out["sga_act_unknown"] = ",".join(self.unknown)[:TARGETS_MAX]
        if self.ops:
            out["sga_act_ops"] = ",".join(sorted(self.ops))
        if self.destroy:
            out["sga_act_destroy"] = ",".join(self.destroy)
        if self.targets:
            out["sga_act_targets"] = ",".join(self.targets)[:TARGETS_MAX]
        return out


def analyze_shell(text: str, facts: Facts | None = None, depth: int = 0) -> Facts:
    facts = facts or Facts()
    if depth > MAX_DEPTH:
        facts.gap("nesting", unsupported=True)
        return facts
    try:
        cmds = commands(tokenize(text))
    except Unsupported as e:
        facts.gap(str(e), unsupported=True)
        return facts
    for cmd in cmds:
        for op, target in cmd.redirects:
            if op.op in (">", ">>", ">|", "&>", "&>>", "<>") and target and target.text != "/dev/null":
                facts.ops.add("write")
            if op.op in ("<<", "<<-") and not op.body_literal and re.search(r"\$\(|`", op.body or ""):
                facts.gap("command-substitution", unsupported=True)  # the shell runs it even for cat
        _simple(cmd, cmd.words, facts, depth)
    return facts


def _opts(words: list[Word], with_arg: set[str]) -> list[Word]:
    """Skip leading options (and the arguments of the ones in ``with_arg``); ``--`` ends them."""
    k = 0
    while k < len(words):
        w = words[k].text
        if w == "--":
            return words[k + 1 :]
        if not w.startswith("-") or w == "-":
            break
        k += 2 if w in with_arg else 1
    return words[k:]


def _flags(words: list[Word]) -> tuple[set[str], list[Word]]:
    """GNU style: every word before ``--`` that starts with ``-`` is an option, wherever it is."""
    flags: set[str] = set()
    operands: list[Word] = []
    ended = False
    for w in words:
        if not ended and w.text == "--":
            ended = True
        elif not ended and w.text.startswith("--") and not w.dynamic:
            flags.add(w.text)
        elif not ended and w.text.startswith("-") and len(w.text) > 1 and not w.dynamic:
            flags.update(f"-{c}" for c in w.text[1:])
        else:
            operands.append(w)
    return flags, operands


def _simple(cmd: Command, words: list[Word], facts: Facts, depth: int, stdin_args: bool = False) -> None:
    while words and not words[0].quoted and _ASSIGN.match(words[0].text):
        words = words[1:]  # VAR=value before the command
    if not words:
        return
    head = words[0]
    if head.dynamic:
        facts.gap("dynamic-command", unsupported=True)
        return
    relative = head.text.startswith(("./", "../"))
    name = head.text if relative else posixpath.basename(head.text)  # /bin/rm is rm
    rest = words[1:]
    if name in TRANSPARENT:
        _simple(cmd, rest, facts, depth, stdin_args)
        return
    if name in UNSUPPORTED_KEYWORDS:
        facts.gap(f"control-flow:{name}", unsupported=True)
        return
    if name == "for":
        return  # the header: for NAME in WORDS (the loop body is its own commands)
    if name in ("eval", "alias", "unalias"):
        facts.gap(name, unsupported=True)
        return
    if name in ("source", "."):
        facts.ops.add("exec")
        facts.gap(f"script:{rest[0].text if rest else '?'}")
        return
    # wrappers: the command they run is what counts
    if name in ("sudo", "doas"):
        _simple(cmd, _opts(rest, _SUDO_ARGS), facts, depth)
        return
    if name in ("nohup", "builtin", "time"):
        _simple(cmd, _opts(rest, set()), facts, depth, stdin_args)
        return
    if name == "command":
        if rest and rest[0].text in ("-v", "-V"):
            return  # looks a command up, runs nothing
        _simple(cmd, _opts(rest, set()), facts, depth, stdin_args)
        return
    if name == "exec":
        _simple(cmd, _opts(rest, {"-a"}), facts, depth, stdin_args)
        return
    if name in ("nice", "ionice", "stdbuf"):
        _simple(cmd, _opts(rest, {"-n", "-c", "-p", "-i", "-o", "-e"}), facts, depth, stdin_args)
        return
    if name == "env":
        if any(w.text.startswith(("-S", "--split-string")) for w in rest):
            facts.gap("env-split-string", unsupported=True)
            return
        _simple(cmd, _opts(rest, {"-u", "-C", "--unset", "--chdir"}), facts, depth, stdin_args)
        return
    if name == "timeout":
        after = _opts(rest, {"-s", "-k", "--signal", "--kill-after"})
        _simple(cmd, after[1:], facts, depth, stdin_args)  # after[0] is the duration
        return
    if name == "xargs":
        after = _opts(rest, {"-n", "-L", "-I", "-d", "-P", "-s", "-a", "-E", "-i", "--max-args",
                             "--delimiter", "--max-procs", "--arg-file"})  # fmt: skip
        _simple(cmd, after, facts, depth, stdin_args=True)
        return
    if name in SHELLS:
        _shell(cmd, rest, facts, depth)
        return
    if name in INTERPRETERS or _PY_VERSIONED.match(name):
        facts.ops.add("exec")
        facts.gap(f"inline:{name}")
        return
    if relative:
        facts.ops.add("exec")
        facts.gap(f"script:{head.text}")
        return
    handler = _modelled(name)
    if handler is not None:
        handler(rest, facts, depth, stdin_args)
        return
    if name in SAFE:
        if name == "tee" and any(not w.text.startswith("-") for w in rest):
            facts.ops.add("write")
        return
    facts.gap(f"unmodelled:{name}")


def _shell(cmd: Command, rest: list[Word], facts: Facts, depth: int) -> None:
    script: Word | None = None
    k = 0
    has_c = False
    while k < len(rest):
        w = rest[k]
        if w.text == "--":
            k += 1
            break
        if w.text.startswith("-") and len(w.text) > 1 and not w.dynamic:
            if "c" in w.text[1:] and not w.text.startswith("--"):
                has_c = True
            k += 2 if w.text in ("-o", "+o", "-O", "+O") else 1
            continue
        break
    operands = rest[k:]
    if has_c:
        if not operands:
            facts.gap("shell-without-command", unsupported=True)
            return
        script = operands[0]
        if script.dynamic:
            facts.gap("dynamic-shell", unsupported=True)  # the outer expansion can add commands
        analyze_shell(script.text, facts, depth + 1)
        return
    if operands:
        facts.ops.add("exec")
        facts.gap(f"script:{operands[0].text}")
        return
    bodies = [op for op, _ in cmd.redirects if op.op in ("<<", "<<-")]
    if bodies:
        for op in bodies:
            if not op.body_literal and re.search(r"[$`]", op.body or ""):
                facts.gap("heredoc-expansion", unsupported=True)
            analyze_shell(op.body or "", facts, depth + 1)
        return
    if cmd.piped or any(op.op in ("<", "<<<") for op, _ in cmd.redirects):
        facts.ops.add("exec")
        facts.gap("shell-reads-stdin")  # curl … | sh: what it runs is not in the command
        return
    # an interactive shell with nothing to run: nothing happens here


# ── modelled destructive commands ───────────────────────────────────────────


def _rm(rest: list[Word], facts: Facts, depth: int, stdin_args: bool) -> None:
    flags, targets = _flags(rest)
    recursive = bool(flags & {"-r", "-R", "--recursive"})
    force = bool(flags & {"-f", "--force"})
    facts.ops.add("delete")
    shown = [*targets, *([Word("<stdin>")] if stdin_args else [])]
    if recursive and force:
        facts.found("rm-recursive-force", shown)
    elif recursive:
        facts.found("rm-recursive", shown)  # asks like -rf (2026-11-17)
    else:
        facts.add_targets(shown)


def _delete_files(rest: list[Word], facts: Facts, depth: int, stdin_args: bool) -> None:
    facts.ops.add("delete")
    facts.add_targets(_flags(rest)[1])


def _find(rest: list[Word], facts: Facts, depth: int, stdin_args: bool) -> None:
    paths: list[Word] = []
    k = 0
    while k < len(rest) and not rest[k].text.startswith(("-", "(", "!", ")")):
        paths.append(rest[k])
        k += 1
    expr = rest[k:]
    shown = paths or [Word(".")]
    j = 0
    while j < len(expr):
        t = expr[j].text
        if t == "-delete":
            facts.ops.add("delete")
            facts.found("find-delete", shown)
        elif t in ("-exec", "-execdir", "-ok", "-okdir"):
            end = next((x for x in range(j + 1, len(expr)) if expr[x].text in (";", "+")), None)
            if end is None:
                facts.gap("find-exec-unterminated", unsupported=True)
                return
            inner = Facts()
            _simple(Command(), expr[j + 1 : end], inner, depth)
            if any(k.startswith("rm-") for k in inner.destroy) or "delete" in inner.ops:
                facts.ops.add("delete")
                facts.found("find-exec-rm", shown)
            for kind in inner.destroy:
                if not kind.startswith("rm-"):
                    facts.found(kind, shown)
            facts.ops |= inner.ops
            for reason in inner.unknown:
                facts.gap(reason, unsupported=inner.parse == "unsupported")
            j = end
        j += 1


def _shred(rest: list[Word], facts: Facts, depth: int, stdin_args: bool) -> None:
    flags, targets = _flags(rest)
    if targets:
        facts.ops.add("write")
        if flags & {"-u", "--remove"}:
            facts.ops.add("delete")
        facts.found("shred-file", targets)


def _git(rest: list[Word], facts: Facts, depth: int, stdin_args: bool) -> None:
    k = 0
    while k < len(rest):  # git's own options before the subcommand
        w = rest[k].text
        if w.startswith("-c"):
            # Configuration can execute an editor, SSH command, filter, pager, etc. Its semantics
            # are not modelled here: keep the raw-text backstop even for a known Git subcommand.
            # Git also accepts the attached spelling: -ccore.editor=command.
            facts.gap("git-config")
            k += 2 if w == "-c" else 1
        elif w == "--config-env" or w.startswith("--config-env="):
            facts.gap("git-config-env")  # the value comes from the execution environment, not this text
            k += 2 if w == "--config-env" else 1
        elif w in ("-C", "--git-dir", "--work-tree", "--namespace"):
            k += 2
        elif w.startswith("-"):
            k += 1
        else:
            break
    if k >= len(rest):
        return
    sub, args = rest[k], rest[k + 1 :]
    if sub.dynamic:
        facts.gap("dynamic-command", unsupported=True)
        return
    flags, operands = _flags(args)
    texts = [a.text for a in args]
    after_dashdash = texts[texts.index("--") + 1 :] if "--" in texts else []
    s = sub.text
    if s == "clean":
        if flags & {"-f", "--force"} and not flags & {"-n", "--dry-run"}:
            facts.ops.add("delete")
            facts.found("git-clean-force", operands or [Word(".")])
        return
    if s == "reset":
        if "--hard" in flags:
            facts.found("git-reset-hard", operands or [Word("HEAD")])
        return
    if s == "checkout":
        if "." in after_dashdash or [w.text for w in operands] == ["."]:
            facts.found("git-checkout-all", [Word(".")])
        return
    if s == "restore":
        if "." in [w.text for w in operands] and not flags & {"--staged", "-S"}:
            facts.found("git-restore-all", [Word(".")])
        return
    if s == "push":
        forced = any(f.startswith("--force") for f in flags) or "-f" in flags
        if forced or any(w.text.startswith("+") for w in operands):
            facts.found("git-push-force", operands[:2])
        return
    if s == "rm":
        if "--cached" in flags:
            return  # untracks only: the files stay
        facts.ops.add("delete")
        facts.add_targets(operands)
        return
    if s not in GIT_SAFE:
        facts.gap(f"unmodelled:git {s}")


def _mkfs(rest: list[Word], facts: Facts, depth: int, stdin_args: bool) -> None:
    _, operands = _flags(rest)
    facts.ops.add("write")
    facts.found("mkfs-format", operands[-1:])


def _dd(rest: list[Word], facts: Facts, depth: int, stdin_args: bool) -> None:
    ops = {w.text.split("=", 1)[0]: w.text.split("=", 1)[1] for w in rest if "=" in w.text}
    if "if" in ops or "of" in ops:
        facts.ops.add("write")
        facts.found("dd-raw-write", [Word(ops.get("of", "<stdout>"))])


def _chmod(rest: list[Word], facts: Facts, depth: int, stdin_args: bool) -> None:
    flags, operands = _flags(rest)
    if not operands:
        return
    facts.ops.add("write")
    mode, targets = operands[0].text, operands[1:]
    recursive = bool(flags & {"-R", "--recursive"})
    open_mode = mode in ("777", "0777", "a+rwx", "ugo+rwx")
    if recursive and open_mode and any(t.text.startswith("/") for t in targets):
        facts.found("chmod-777-root", targets)


_MODELLED = {
    "rm": _rm,
    "rmdir": _delete_files,
    "unlink": _delete_files,
    "find": _find,
    "shred": _shred,
    "git": _git,
    "mkfs": _mkfs,
    "dd": _dd,
    "chmod": _chmod,
}


def _modelled(name: str) -> Any:
    if name.startswith("mkfs."):
        return _mkfs
    return _MODELLED.get(name)


# ── tool calls ──────────────────────────────────────────────────────────────


def analyze_call(tool: str, args: dict[str, Any]) -> Facts | None:
    """Facts for a tool call, or None when the tool is outside the model (MCP tools, web, …): the raw
    rules alone judge those."""
    if tool in SHELL_TOOLS:
        value = next((args[k] for k in COMMAND_KEYS if args.get(k) is not None), None)
        if isinstance(value, str):
            return analyze_shell(value)
        if isinstance(value, list) and value and all(isinstance(x, str) for x in value):
            # An argv list (Codex: ["bash", "-lc", "…"]): already words, nothing to split or unquote.
            facts = Facts()
            _simple(Command(), [Word(x, quoted=True) for x in value], facts, 0)
            return facts
        return None
    if tool == "PowerShell":
        f = Facts()
        f.gap("shell:powershell", unsupported=True)
        return f
    if tool in tools.FILE_WRITE:
        f = Facts(ops={"write"})
        path = args.get("file_path") or args.get("path") or args.get("notebook_path")
        if isinstance(path, str):
            f.targets.append(path)
        patch = args.get("patch") or args.get("input")
        if tool == "apply_patch" and isinstance(patch, str):
            for m in re.finditer(r"^\*\*\* Delete File: (.+)$", patch, re.M):
                f.ops.add("delete")
                f.targets.append(m.group(1).strip())
        return f
    if tool in tools.CLAUDE_READ_ONLY or tool == "read":
        return Facts(ops={"read"})
    return None


def labels_for(event: AgentEvent) -> dict[str, str]:
    if event.kind is not EventKind.TOOL_CALL:
        return {}
    if event.labels.get("openclaw.tool_kind") == "code_mode_exec":
        # OpenClaw Code Mode's outer call carries JavaScript, not a shell command: never read it as one (it
        # could come out "ok" and switch the raw-text check off). Its inner calls are judged on their own.
        facts = Facts()
        facts.gap("language:javascript", unsupported=True)
        return facts.labels()
    p = event.payload
    args = getattr(p, "arguments", None)
    facts = analyze_call(getattr(p, "tool", "") or "", args if isinstance(args, dict) else {})
    return facts.labels() if facts is not None else {}
