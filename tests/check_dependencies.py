#!/usr/bin/env python3
# Copyright 2026 Zhijie He
# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.
#
# Static dependency-order check for the generated dist scripts.
#
# Simulates the runtime execution order of every UPPERCASE global: the
# Process section runs containers in source order, each container expands
# its nested RunStep children and bare calls inline, and every assignment
# or reference inside a body happens at that point. A global referenced
# (without a :- / - / = / + default guard) before any assignment executes
# - or never assigned at all - aborts the script under set -u, so both
# classes fail the check. lowercase variables are locals by project
# convention and are not checked.
#
# Usage: python3 tests/check_dependencies.py dist/*.sh

import re
import sys

FUNC_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\(\) \{$')
NESTED_RE = re.compile(r'^(\s+)([A-Za-z_][A-Za-z0-9_]*)\(\) \{$')
END_RE = re.compile(r'^\}$')
ASSIGN_RE = re.compile(
    r'^\s*(?:export\s+)?(?:local\s+)?([A-Z_][A-Z0-9_]*)\+?=')
CASE_ASSIGN_RE = re.compile(
    r'^\s*\S+\)\s+([A-Z_][A-Z0-9_]*)\+?=')
RUNSTEP_RE = re.compile(r'^\s*RunStep\s+"[^"]*"\s+([A-Za-z_][A-Za-z0-9_]*)')
BARE_CALL_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s|$)')
HEREDOC_RE = re.compile(r'<<-?\s*["\']?([A-Za-z_][A-Za-z0-9_]*)["\']?\s*$')
USE_RE = re.compile(r'(?<!\\)\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}'
                    r'|(?<!\\)\$([A-Za-z_][A-Za-z0-9_]*)')

# Provided by the kernel or the operator, never assigned inside the script.
SAFE_ENV = {
    'PATH', 'HOME', 'USER', 'UID', 'PWD', 'OLDPWD', 'SHLVL', 'EUID',
    'SUDO_USER', 'SUDO_GID', 'SUDO_COMMAND', 'RANDOM', 'SECONDS',
    'HOSTNAME', 'OPTARG', 'OPTIND', 'LINENO', 'REPLY', 'IFS', 'TERM',
    'LANG', 'LC_ALL', 'SSH_CLIENT', 'SSH_TTY', 'SSH_CONNECTION',
    'DEBIAN_FRONTEND', 'ZJDEPLOY_FORCE', 'ZJDEPLOY_STATE_DIR',
    'DOCKER_APT_DISTRO', 'FRR_APT_LINE',  # operator-overridable knobs
    # optional operator knobs - every unsafe use is behind a -n guard
    'DEFAULT_USERNAME', 'GPG_HOME_OWNER',
}


def unsafe_uses(line):
    """Yield UPPERCASE variable names referenced without a default guard."""
    for m in USE_RE.finditer(line):
        name = m.group(1) or m.group(2)
        if not name or not name[0].isupper():
            continue
        if m.group(1):
            body = m.group(0)[2 + len(name):len(m.group(0)) - 1]
            if body[:2] in (':-', ':=') or body[:1] in ('-', '=', '+', '#', '%', '/'):
                continue  # ${VAR:-default} and friends are set -u safe
            if body.startswith('[') or body.startswith('#'):
                continue  # array element / string length of an assigned array
        yield name


class Script:
    def __init__(self, path):
        self.path = path
        self.lines = open(path, errors='replace').read().splitlines()
        # bodies: func -> (start, end); nested defs are separate scopes
        self.bodies = {}
        self._map_bodies()

    def _map_bodies(self):
        stack = []  # (indent, name, start)
        for i, line in enumerate(self.lines, 1):
            m_top = FUNC_RE.match(line)
            m_nested = NESTED_RE.match(line)
            if m_top:
                name = m_top.group(1)
                if name not in self.bodies:
                    self.bodies[name] = [i, None]
                stack = [(0, name, i)]
                continue
            if m_nested:
                name = m_nested.group(2)
                if name not in self.bodies:
                    self.bodies[name] = [i, None]
                stack.append((len(m_nested.group(1)), name, i))
                continue
            if not stack:
                continue
            stripped = line.strip()
            if stripped != '}':
                continue
            want = stack[-1][0]
            if len(line) - len(line.lstrip()) == want:
                _, name, _ = stack.pop()
                self.bodies[name][1] = i

    def in_body(self, i):
        return any(a <= i <= b for a, b in self.bodies.values())

    def owner(self, i):
        for name, (a, b) in self.bodies.items():
            if a <= i <= b:
                return name, a, b
        return None, None, None

    def heredoc_lines(self):
        """Lines inside heredoc bodies are literal text - no $ semantics."""
        skip = set()
        delim = None
        for i, line in enumerate(self.lines, 1):
            if delim:
                skip.add(i)
                if line.strip() == delim:
                    delim = None
                continue
            m = HEREDOC_RE.search(line)
            if m:
                delim = m.group(1)
        return skip

    def check(self):
        events = []   # (key, kind, var, line)
        uses = []     # (key, var, func, line)
        dispatch = {}  # func -> earliest dispatch key
        bodies = {k: tuple(v) for k, v in self.bodies.items()}

        def body_lines(name, prefix):
            a, b = bodies[name]
            out = []
            for i in range(a + 1, b):
                out.append((prefix + (i,), i))
            return out

        def nested_ranges(name):
            a, b = bodies[name]
            return sorted((x[0], x[1]) for k, x in bodies.items()
                          if k != name and a < x[0] < b)

        def expand(name, prefix, active):
            if name in active:
                return  # recursion guard
            active = active | {name}
            ranges = nested_ranges(name)
            a, b = bodies[name]
            for i in range(a + 1, b):
                if any(x[0] <= i <= x[1] for x in ranges):
                    continue  # nested body runs at its own dispatch point
                line = self.lines[i - 1]
                key = prefix + (i,)
                m = ASSIGN_RE.match(line) or CASE_ASSIGN_RE.match(line)
                if m:
                    events.append((key, 'assign', m.group(1), i))
                    continue
                m = RUNSTEP_RE.match(line)
                nm = BARE_CALL_RE.match(line)
                child = None
                if m:
                    child = m.group(1)
                elif nm and nm.group(1) in bodies and nm.group(1) != name:
                    child = nm.group(1)
                if child and child not in active:
                    expand(child, key, active)

        # top-level walk (outside any body)
        i = 1
        n = len(self.lines)
        while i <= n:
            if self.in_body(i):
                _, a, b = self.owner(i)
                i = b + 1
                continue
            line = self.lines[i - 1]
            key = (0, i)
            m = ASSIGN_RE.match(line) or CASE_ASSIGN_RE.match(line)
            if m:
                events.append((key, 'assign', m.group(1), i))
                i += 1
                continue
            m = RUNSTEP_RE.match(line)
            nm = BARE_CALL_RE.match(line)
            child = None
            if m and m.group(1) in bodies:
                child = m.group(1)
            elif nm and nm.group(1) in bodies:
                child = nm.group(1)
            if child:
                dispatch.setdefault(child, key)
                expand(child, key, set())
            i += 1

        # uses: recorded at each function's earliest dispatch key
        def record_uses(name, prefix, active):
            if name in active:
                return
            active = active | {name}
            ranges = nested_ranges(name)
            a, b = bodies[name]
            skip = self.heredoc_lines()
            for i in range(a + 1, b):
                if i in skip or any(x[0] <= i <= x[1] for x in ranges):
                    continue
                line = self.lines[i - 1]
                key = prefix + (i,)
                m = RUNSTEP_RE.match(line)
                nm = BARE_CALL_RE.match(line)
                child = None
                if m:
                    child = m.group(1)
                elif nm and nm.group(1) in bodies and nm.group(1) != name:
                    child = nm.group(1)
                if child and child not in active:
                    record_uses(child, key, active)
                    continue

                for var in unsafe_uses(line):
                    uses.append((key, var, name, i))

        for func, key in dispatch.items():
            record_uses(func, key, set())

        problems = []
        for use_key, var, func, line in sorted(uses):
            if var in SAFE_ENV:
                continue
            var_events = sorted(e for e in events if e[2] == var)
            if not var_events:
                problems.append(
                    f'{self.path}:{line}: {var} referenced in {func}() '
                    f'but never assigned')
            elif var_events[0][0] > use_key:
                akey, _, _, aline = var_events[0]
                problems.append(
                    f'{self.path}:{line}: {var} referenced in {func}() '
                    f'before it is assigned (first assigned at '
                    f'{self.path}:{aline})')
        return problems


def main():
    total = 0
    for path in sys.argv[1:]:
        problems = Script(path).check()
        for p in problems:
            print(p)
        total += len(problems)
    if total:
        print(f'\n{total} dependency-order problem(s) found')
        sys.exit(1)
    print('all dependency checks passed')


if __name__ == '__main__':
    main()