#!/usr/bin/env python3
"""
Zero-dependency mutation tester. Pure stdlib, works on native Windows.

    python mutate.py --target titan_gate/canonical.py --tests tests/ --list
    python mutate.py --target titan_gate/canonical.py --tests tests/ --max 40

For each mutation site it rewrites ONE operator, runs the given pytest scope,
and records killed (suite went red) or SURVIVED (suite stayed green -- a change
your tests cannot see).

The target file is restored in a finally block and on SIGINT. A .mutbak copy is
written before the first mutation and removed on clean exit; if the process is
killed hard, restore by hand from that file.

Baseline discipline: the harness first round-trips the target through
ast.unparse WITHOUT mutating and runs the suite. If that is not green, it
aborts -- otherwise every "killed" result could be an unparse artifact rather
than a real detection.
"""
import argparse
import ast
import copy
import os
import shutil
import signal
import subprocess
import sys
import time

CMP_SWAP = {
    ast.Lt: ast.LtE, ast.LtE: ast.Lt,
    ast.Gt: ast.GtE, ast.GtE: ast.Gt,
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
    ast.Is: ast.IsNot, ast.IsNot: ast.Is,
    ast.In: ast.NotIn, ast.NotIn: ast.In,
}
BIN_SWAP = {
    ast.Add: ast.Sub, ast.Sub: ast.Add,
    ast.Mult: ast.Div, ast.Div: ast.Mult,
    ast.FloorDiv: ast.Div, ast.Mod: ast.Mult,
    ast.BitAnd: ast.BitOr, ast.BitOr: ast.BitAnd,
    ast.LShift: ast.RShift, ast.RShift: ast.LShift,
}
BOOL_SWAP = {ast.And: ast.Or, ast.Or: ast.And}


def _sites(tree):
    """Every mutation opportunity in the tree, in source order."""
    found = []
    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", None)
        if isinstance(node, ast.Compare):
            for i, op in enumerate(node.ops):
                if type(op) in CMP_SWAP:
                    found.append((id(node), "cmp", i, lineno,
                                  "%s -> %s" % (type(op).__name__,
                                                CMP_SWAP[type(op)].__name__)))
        elif isinstance(node, ast.BinOp) and type(node.op) in BIN_SWAP:
            found.append((id(node), "bin", 0, lineno,
                          "%s -> %s" % (type(node.op).__name__,
                                        BIN_SWAP[type(node.op)].__name__)))
        elif isinstance(node, ast.BoolOp) and type(node.op) in BOOL_SWAP:
            found.append((id(node), "bool", 0, lineno,
                          "%s -> %s" % (type(node.op).__name__,
                                        BOOL_SWAP[type(node.op)].__name__)))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            found.append((id(node), "not", 0, lineno, "drop `not`"))
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                found.append((id(node), "const", 0, lineno,
                              "%r -> %r" % (node.value, not node.value)))
            elif isinstance(node.value, int) and not isinstance(node.value, bool):
                found.append((id(node), "const", 0, lineno,
                              "%r -> %r" % (node.value, node.value + 1)))
    found.sort(key=lambda t: (t[3] or 0, t[1], t[2], t[4]))
    return found


def _apply(tree, target_id, kind, idx):
    """Mutate the single node whose id matches, in a fresh tree copy."""
    for node in ast.walk(tree):
        if id(node) != target_id:
            continue
        if kind == "cmp":
            node.ops[idx] = CMP_SWAP[type(node.ops[idx])]()
        elif kind == "bin":
            node.op = BIN_SWAP[type(node.op)]()
        elif kind == "bool":
            node.op = BOOL_SWAP[type(node.op)]()
        elif kind == "not":
            return node.operand           # caller splices via parent rebuild
        elif kind == "const":
            if isinstance(node.value, bool):
                node.value = not node.value
            else:
                node.value = node.value + 1
        return None
    raise LookupError("mutation site vanished")


def _drop_not(tree, target_id):
    class T(ast.NodeTransformer):
        def visit_UnaryOp(self, node):
            self.generic_visit(node)
            if id(node) == target_id and isinstance(node.op, ast.Not):
                return node.operand
            return node
    return ast.fix_missing_locations(T().visit(tree))


def run_tests(pytest_args, timeout):
    # -B / PYTHONDONTWRITEBYTECODE: .pyc validation is (mtime_seconds, size).
    # Same-size mutations written within one second reuse stale bytecode and
    # get falsely reported as SURVIVED.
    cmd = [sys.executable, "-B", "-m", "pytest", "-x", "-q", "--no-header", "-p",
           "no:cacheprovider"] + pytest_args
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=env)
        return p.returncode, (p.stdout or "")[-400:]
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--tests", nargs="+", required=True,
                    help="pytest args, e.g. tests/ or tests/test_canonical.py")
    ap.add_argument("--max", type=int, default=0, help="0 = all sites")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--list", action="store_true", help="enumerate sites, run nothing")
    args, passthrough = ap.parse_known_args()
    # Anything argparse does not recognise is forwarded verbatim to pytest,
    # so `-k "canonical or chain"` works without quoting gymnastics.
    pytest_args = list(args.tests) + list(passthrough)

    # newline="" on BOTH sides: never translate line endings. Without it,
    # restore() rewrites a CRLF file as LF (or vice versa) and leaves the
    # target dirty even on a clean exit.
    original = open(args.target, "r", encoding="utf-8", newline="").read()
    tree = ast.parse(original)
    sites = _sites(tree)

    if args.list:
        print("%d mutation sites in %s" % (len(sites), args.target))
        for i, (_, kind, _, line, desc) in enumerate(sites):
            print("  [%3d] line %-4s %-6s %s" % (i, line, kind, desc))
        return 0

    if args.max:
        sites = sites[:args.max]

    backup = args.target + ".mutbak"
    shutil.copy2(args.target, backup)

    def restore(*_):
        with open(args.target, "w", encoding="utf-8", newline="") as f:
            f.write(original)
    signal.signal(signal.SIGINT, lambda *a: (restore(), sys.exit(130)))

    killed, survived, errored = [], [], []
    t0 = time.time()
    try:
        # Baseline: unparsed-but-unmutated must be green, or results are noise.
        with open(args.target, "w", encoding="utf-8", newline="") as f:
            f.write(ast.unparse(ast.parse(original)))
        rc, tail = run_tests(pytest_args, args.timeout)
        if rc != 0:
            print("BASELINE NOT GREEN after ast.unparse round-trip (rc=%d)." % rc)
            print("Aborting: every 'killed' below would be an unparse artifact.")
            print(tail)
            return 2
        print("baseline green | %d sites | scope: %s\n" % (len(sites), " ".join(pytest_args)))

        for i, (nid, kind, idx, line, desc) in enumerate(sites):
            mtree = ast.parse(original)
            # ids differ per parse, so re-find the site positionally
            msites = _sites(mtree)
            if i >= len(msites):
                errored.append((line, desc, "site drift"))
                continue
            mnid, mkind, midx, mline, mdesc = msites[i]
            try:
                if mkind == "not":
                    mtree = _drop_not(mtree, mnid)
                else:
                    _apply(mtree, mnid, mkind, midx)
                src = ast.unparse(ast.fix_missing_locations(mtree))
            except Exception as e:
                errored.append((mline, mdesc, repr(e)))
                continue

            with open(args.target, "w", encoding="utf-8", newline="") as f:
                f.write(src)
            rc, tail = run_tests(pytest_args, args.timeout)
            if rc == 0:
                survived.append((mline, mdesc))
                mark = "SURVIVED"
            else:
                killed.append((mline, mdesc))
                mark = "killed  "
            print("[%3d/%d] %s line %-4s %s" % (i + 1, len(sites), mark, mline, mdesc))
    finally:
        restore()
        if os.path.exists(backup):
            os.remove(backup)

    total = len(killed) + len(survived)
    print("\n" + "=" * 62)
    print("MUTATION SCORE  %d/%d killed = %.1f%%   (%s)"
          % (len(killed), total, 100.0 * len(killed) / total if total else 0.0,
             args.target))
    print("elapsed %.0fs, %d harness errors" % (time.time() - t0, len(errored)))
    if survived:
        print("\nSURVIVORS -- changes your tests cannot see:")
        for line, desc in survived:
            print("  line %-4s %s" % (line, desc))
        print("\nEach survivor is either a missing test or dead code. Both are findings.")
    print("=" * 62)
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
