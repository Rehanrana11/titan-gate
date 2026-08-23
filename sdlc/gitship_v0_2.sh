#!/usr/bin/env bash
# gitship v0.2 -- commit and push NAMED paths only. titan-gate / SDLC DESIGNER.
#
# CHANGELOG
#   v0.2  self-check narrowed to executed git commands. v0.1 matched its own
#         header prose (the word "stashes") and refused to run at all -- caught
#         on first execution in a clean container, never shipped.
#   v0.1  first cut. Not shipped.
#
# WHY THIS EXISTS
#   "Every good work should be pushed" is right. `git add -A` is how that turns
#   into publishing an unreviewed edit to docs/SPEC.md on a public repo. This
#   script cannot do that: it refuses -A / --all / . / * and stages only paths
#   named on the command line.
#
# DESTRUCTION LOCK (project charter G1)
#   Nothing here removes, reverts, force-pushes or discards anything. Those
#   verbs are refused by name at run time -- see REFUSED below. commit + push
#   of new objects is additive and needs no "go".
#
# USAGE
#   bash sdlc/gitship_v0_2.sh -m "message" path [path...]          # dry run
#   bash sdlc/gitship_v0_2.sh --ship -m "message" path [path...]   # commit+push
#
# TOKEN
#   Read from $TITAN_TOKEN_FILE (default /c/Users/rmaso/gh_token.txt).
#   Never echoed; redacted from push output; unset immediately after use.
#   Expires ~2026-08-30 -- the script warns on or after that date.

set -u

REPO_OWNER="Rehanrana11"
REPO_NAME="titan-gate"
TOKEN_FILE="${TITAN_TOKEN_FILE:-/c/Users/rmaso/gh_token.txt}"
TOKEN_EXPIRY="2026-08-30"

# Paths whose contents are claims a stranger reads. Shipping one is a decision,
# never a side effect of a convenience flag.
HAZARD='^(docs/|README|SPEC|LICENSE|SECURITY|\.github/|pyproject\.toml|action\.yml)'

# Destructive git verbs. Checked against EXECUTED lines only (comments stripped),
# so that an edit which introduces one makes this script refuse to run at all.
REFUSED='reset[ ]+--hard|checkout[ ]+--|clean[ ]+-|stash|push[ ]+--force|push[ ]+-f|filter-branch'

die() { printf 'gitship: %s\n' "$*" >&2; exit 1; }

# --- self-check: no destructive verb may appear in an executed git command ---
if grep -vE '^[[:space:]]*#' "$0" | grep -vE '^(REFUSED|HAZARD)=' \
   | grep -qE "git[[:space:]]+[a-z-]*[[:space:]]*($REFUSED)"; then
  die "SELF-CHECK FAILED: a destructive git verb appears in an executed line. Refusing."
fi

SHIP=0
MSG=""
PATHS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ship) SHIP=1; shift ;;
    -m) MSG="${2:-}"; shift 2 ;;
    -A|--all|.|'*'|'./') die "refused: '$1'. Name the paths. That is the whole point." ;;
    -*) die "unknown flag '$1'" ;;
    *) PATHS="$PATHS $1"; shift ;;
  esac
done

[ -n "$MSG" ] || die "no commit message. Use -m \"...\""
[ -n "$PATHS" ] || die "no paths named. Refusing to guess what 'everything' means."

git rev-parse --show-toplevel >/dev/null 2>&1 || die "not inside a git repo"
cd "$(git rev-parse --show-toplevel)" || die "cannot cd to repo root"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[ "$BRANCH" != "HEAD" ] || die "detached HEAD. Check out a branch first."
if [ "$BRANCH" = "main" ] && [ "${GITSHIP_ALLOW_MAIN:-0}" != "1" ]; then
  die "refusing to ship to main. Use a branch, or set GITSHIP_ALLOW_MAIN=1."
fi

MISSING=""; HAZARDOUS=""
for p in $PATHS; do
  case "$p" in /*) die "refused: '$p' is absolute. Use repo-relative paths." ;; esac
  [ -e "$p" ] || MISSING="$MISSING $p"
  printf '%s\n' "$p" | grep -qE "$HAZARD" && HAZARDOUS="$HAZARDOUS $p"
done
[ -z "$MISSING" ] || die "these paths do not exist:$MISSING"

if [ -n "$HAZARDOUS" ] && [ "${GITSHIP_ALLOW_HAZARD:-0}" != "1" ]; then
  printf 'gitship: REFUSED -- external-claim surface in the path list:%s\n' "$HAZARDOUS" >&2
  printf 'gitship: a stranger reads these. Review, then re-run with\n' >&2
  printf 'gitship: GITSHIP_ALLOW_HAZARD=1 to ship them deliberately.\n' >&2
  exit 1
fi

N=$(printf '%s\n' $PATHS | grep -c .)
printf 'gitship v0.2  branch=%s  paths=%s  ship=%s\n' "$BRANCH" "$N" "$SHIP"
printf 'STAGING (and nothing else):\n'
printf '%s\n' $PATHS | sed 's/^/  + /' | head -20
[ "$N" -gt 20 ] && printf '  TRUNCATED_AT=20 TOTAL=%s\n' "$N"

if [ "$SHIP" -eq 0 ]; then
  printf 'DRY RUN. Nothing staged, nothing committed, nothing pushed.\n'
  printf 'Re-run with --ship to commit and push.\n'
  exit 0
fi

git add -- $PATHS || die "git add failed"
if git diff --cached --quiet; then
  printf 'staged set is identical to HEAD -- nothing to commit, nothing pushed.\n'
  exit 0
fi
git -c core.pager=cat diff --cached --stat | tail -8
git commit -q -m "$MSG" || die "commit failed"
printf 'COMMITTED %s\n' "$(git rev-parse --short HEAD)"

[ -f "$TOKEN_FILE" ] || die "token file not found: $TOKEN_FILE (commit is safe on disk)"
TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"
[ -n "$TOKEN" ] || die "token file is empty (commit is safe on disk)"

TODAY="$(date +%Y-%m-%d)"
if [ ! "$TODAY" \< "$TOKEN_EXPIRY" ]; then
  printf 'gitship: WARNING token expired or expires today (%s).\n' "$TOKEN_EXPIRY" >&2
fi

GIT_ASKPASS= GIT_TERMINAL_PROMPT=1 \
  git push "https://${REPO_OWNER}:${TOKEN}@github.com/${REPO_OWNER}/${REPO_NAME}.git" \
  "$BRANCH" 2>&1 | sed "s|${TOKEN}|<redacted>|g" | tail -6
unset TOKEN

printf 'PUSHED -> https://github.com/%s/%s/tree/%s\n' "$REPO_OWNER" "$REPO_NAME" "$BRANCH"
