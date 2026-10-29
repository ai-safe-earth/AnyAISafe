#!/bin/sh
# aisafe-audit: ignore-file
# ai-safety-audit evaluate step (phase 5). Detects the project's test command and prints it,
# then resolves `aisafe` through the same pinned bootstrap chain as audit.sh and runs
# `aisafe evaluate` against AISAFE_EVALUATE_URL (the project's own chat endpoint) or over
# AISAFE_EVALUATE_TRANSCRIPTS (a JSONL file of recorded conversations; nothing is sent).
# Nothing runs unless AISAFE_EVALUATE_RUN=1: the tests and the endpoint run may call model
# providers and cost money. AISAFE_EVALUATE_SKIP_TESTS=1 leaves the project's tests out.
# AISAFE_EVALUATE_FAMILIES replaces the default scenario families. Extra arguments are passed
# to `aisafe evaluate` unchanged (--request-template, --response-path, --header).
# This script never adds --i-have-authorization: a non-loopback target needs the user to add
# it themselves, and nothing here is ever pointed at real users.
# The report goes under .aisafe-audit/ like every other artefact of the flow; the next audit
# reads it there as observed behaviour (AUD-1106, AUD-1108) whether or not .gitignore lists
# the directory.
set -u
AISAFE_VERSION="0.1.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
run="${AISAFE_EVALUATE_RUN:-0}"
skip_tests="${AISAFE_EVALUATE_SKIP_TESTS:-0}"
url="${AISAFE_EVALUATE_URL:-}"
transcripts="${AISAFE_EVALUATE_TRANSCRIPTS:-}"
families="${AISAFE_EVALUATE_FAMILIES:-crisis_disclosure goodbye_pressure identity_question manipulation_elicitation benign_traffic}"
status=0
report_dir=".aisafe-audit"
evaluation_report="$report_dir/evaluation-report.json"

# --- 1. Test command, from manifests (first match wins) ---------------------
test_cmd=""
if [ -f pyproject.toml ] || [ -f pytest.ini ] || [ -f setup.cfg ]; then
  test_cmd="pytest"
elif [ -f package.json ] && grep -q '"test"[[:space:]]*:' package.json; then
  test_cmd="npm test"
elif [ -f go.mod ]; then
  test_cmd="go test ./..."
elif [ -f Cargo.toml ]; then
  test_cmd="cargo test"
fi

if [ -z "$test_cmd" ]; then
  echo "tests: no test command detected (looked for pyproject.toml/pytest.ini/setup.cfg, package.json test script, go.mod, Cargo.toml)"
else
  echo "tests: $test_cmd"
  if [ "$skip_tests" = "1" ]; then
    echo "tests: skipped (AISAFE_EVALUATE_SKIP_TESTS=1)"
  elif [ "$run" = "1" ]; then
    # shellcheck disable=SC2086  # intentional word splitting of the detected command
    if ! $test_cmd; then
      echo "tests: FAILED ($test_cmd exited non-zero)" >&2
      status=1
    fi
  else
    echo "tests: not run (set AISAFE_EVALUATE_RUN=1 to run)"
  fi
fi

# --- 2. aisafe through the same bootstrap chain as audit.sh -------------------
have_aisafe() {
  command -v aisafe >/dev/null 2>&1 || command -v uvx >/dev/null 2>&1 || command -v pipx >/dev/null 2>&1
}

# One line on stderr saying which aisafe is about to run (hard rule 8 of SKILL.md).
announce_aisafe() {
  if command -v aisafe >/dev/null 2>&1; then
    v=$(aisafe --version 2>/dev/null | sed 's/^aisafe //' || true); [ -n "$v" ] || v=unknown
    echo "aisafe: $(command -v aisafe) version $v (pinned $AISAFE_VERSION)" >&2
  elif command -v uvx >/dev/null 2>&1; then
    echo "aisafe: uvx aisafe==$AISAFE_VERSION (pinned $AISAFE_VERSION)" >&2
  elif command -v pipx >/dev/null 2>&1; then
    echo "aisafe: pipx aisafe==$AISAFE_VERSION (pinned $AISAFE_VERSION)" >&2
  fi
}

run_aisafe() {
  if command -v aisafe >/dev/null 2>&1; then
    aisafe "$@"
  elif command -v uvx >/dev/null 2>&1; then
    uvx --from "aisafe==$AISAFE_VERSION" aisafe "$@"
  elif command -v pipx >/dev/null 2>&1; then
    pipx run --spec "aisafe==$AISAFE_VERSION" aisafe "$@"
  else
    return 127
  fi
}

# Summary counts from an evaluation report. `summary` is the first object carrying these
# keys (by_family comes after it), so the first match is the right one. Only `passed`
# means passed; none of the others is ever folded into it.
print_evaluation_summary() {
  for key in sent passed failed missing errors skipped inconclusive observed; do
    value=$(grep -oE "\"$key\"[[:space:]]*:[[:space:]]*[0-9]+" "$1" | head -n 1 | grep -oE '[0-9]+$')
    echo "evaluate $key: ${value:-?}"
  done
  echo "evaluate: only 'passed' means passed; failed, missing, errors, skipped, inconclusive and observed are separate"
}

# --- 3. aisafe evaluate, against an endpoint or over transcripts --------------
if [ -z "$url" ] && [ -z "$transcripts" ]; then
  echo "evaluate: no endpoint or transcripts given (set AISAFE_EVALUATE_URL to a loopback URL you are authorised to test, or AISAFE_EVALUATE_TRANSCRIPTS to a JSONL file)"
  exit "$status"
fi

if ! have_aisafe; then
  echo "evaluate skipped: aisafe not importable in target" >&2
  exit "$status"
fi

if [ -n "$transcripts" ]; then
  echo "evaluate: aisafe evaluate --transcripts $transcripts -o $evaluation_report"
  echo "evaluate: transcripts are read locally; nothing is sent anywhere"
  if [ "$run" = "1" ]; then
    mkdir -p "$report_dir"
    announce_aisafe
    if ! run_aisafe evaluate --transcripts "$transcripts" -o "$evaluation_report" "$@"; then
      echo "evaluate: exited non-zero (1 = a tactic or an identity claim was observed, 2 = errors or unreadable input)" >&2
      status=1
    fi
    if [ -f "$evaluation_report" ]; then
      print_evaluation_summary "$evaluation_report"
    fi
  else
    echo "evaluate: not run (set AISAFE_EVALUATE_RUN=1 to run)"
  fi
else
  echo "evaluate: aisafe evaluate $url --families $families -o $evaluation_report"
  echo "evaluate: a non-loopback target needs --i-have-authorization; this script never adds it, and nothing here is run against real users"
  if [ "$run" = "1" ]; then
    mkdir -p "$report_dir"
    announce_aisafe
    # shellcheck disable=SC2086  # $families is a space-separated list by design
    if ! run_aisafe evaluate "$url" --families $families -o "$evaluation_report" "$@"; then
      echo "evaluate: exited non-zero (1 = a scenario failed, 2 = errors/skipped/inconclusive present)" >&2
      status=1
    fi
    if [ -f "$evaluation_report" ]; then
      print_evaluation_summary "$evaluation_report"
    fi
  else
    echo "evaluate: not run (set AISAFE_EVALUATE_RUN=1 to run)"
  fi
fi

exit "$status"
