# ai-safety-audit evaluate step (phase 5), PowerShell mirror of evaluate.sh.
# aisafe-audit: ignore-file
# Detects the project's test command and prints it, then resolves `aisafe` through the same
# pinned bootstrap chain as audit.ps1 and runs `aisafe evaluate` against AISAFE_EVALUATE_URL
# (the project's own chat endpoint) or over AISAFE_EVALUATE_TRANSCRIPTS (a JSONL file of
# recorded conversations; nothing is sent). Nothing runs unless AISAFE_EVALUATE_RUN=1: the
# tests and the endpoint run may call model providers and cost money.
# AISAFE_EVALUATE_SKIP_TESTS=1 leaves the project's tests out. AISAFE_EVALUATE_FAMILIES
# replaces the default scenario families. Extra arguments are passed to `aisafe evaluate`
# unchanged. This script never adds --i-have-authorization: a non-loopback target needs the
# user to add it themselves, and nothing here is ever pointed at real users.
# The report goes under .aisafe-audit/ like every other artefact of the flow; the next audit
# reads it there as observed behaviour (AUD-1106, AUD-1108) whether or not .gitignore lists
# the directory.
$AISAFE_VERSION = "0.2.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
$scriptArgs = @($args)
$run = if ($env:AISAFE_EVALUATE_RUN) { $env:AISAFE_EVALUATE_RUN } else { "0" }
$skipTests = if ($env:AISAFE_EVALUATE_SKIP_TESTS) { $env:AISAFE_EVALUATE_SKIP_TESTS } else { "0" }
$url = if ($env:AISAFE_EVALUATE_URL) { $env:AISAFE_EVALUATE_URL } else { "" }
$transcripts = if ($env:AISAFE_EVALUATE_TRANSCRIPTS) { $env:AISAFE_EVALUATE_TRANSCRIPTS } else { "" }
$families = if ($env:AISAFE_EVALUATE_FAMILIES) { $env:AISAFE_EVALUATE_FAMILIES } else { "crisis_disclosure goodbye_pressure identity_question manipulation_elicitation benign_traffic" }
$familyList = @($families -split '\s+' | Where-Object { $_ })
$status = 0
$reportDir = ".aisafe-audit"
$evaluationReport = "$reportDir/evaluation-report.json"

# --- 1. Test command, from manifests (first match wins) ---------------------
$testCmd = $null
if ((Test-Path pyproject.toml) -or (Test-Path pytest.ini) -or (Test-Path setup.cfg)) {
    $testCmd = @("pytest")
} elseif ((Test-Path package.json) -and (Select-String -Path package.json -Pattern '"test"\s*:' -Quiet)) {
    $testCmd = @("npm", "test")
} elseif (Test-Path go.mod) {
    $testCmd = @("go", "test", "./...")
} elseif (Test-Path Cargo.toml) {
    $testCmd = @("cargo", "test")
}

if ($null -eq $testCmd) {
    Write-Output "tests: no test command detected (looked for pyproject.toml/pytest.ini/setup.cfg, package.json test script, go.mod, Cargo.toml)"
} else {
    Write-Output "tests: $($testCmd -join ' ')"
    if ($skipTests -eq "1") {
        Write-Output "tests: skipped (AISAFE_EVALUATE_SKIP_TESTS=1)"
    } elseif ($run -eq "1") {
        $testArgs = @($testCmd | Select-Object -Skip 1)
        & $testCmd[0] @testArgs
        if ($LASTEXITCODE -ne 0) {
            [Console]::Error.WriteLine("tests: FAILED ($($testCmd -join ' ') exited non-zero)")
            $status = 1
        }
    } else {
        Write-Output "tests: not run (set AISAFE_EVALUATE_RUN=1 to run)"
    }
}

# --- 2. aisafe through the same bootstrap chain as audit.ps1 ------------------
function Test-Aisafe {
    return [bool]((Get-Command aisafe -ErrorAction SilentlyContinue) -or
                  (Get-Command uvx -ErrorAction SilentlyContinue) -or
                  (Get-Command pipx -ErrorAction SilentlyContinue))
}

# One line on stderr saying which aisafe is about to run (hard rule 8 of SKILL.md).
function Write-WhichAisafe {
    if (Get-Command aisafe -ErrorAction SilentlyContinue) {
        $resolved = (Get-Command aisafe).Source
        $version = (& aisafe --version 2>$null) -replace '^aisafe ', ''
        if (-not $version) { $version = "unknown" }
        [Console]::Error.WriteLine("aisafe: $resolved version $version (pinned $AISAFE_VERSION)")
    } elseif (Get-Command uvx -ErrorAction SilentlyContinue) {
        [Console]::Error.WriteLine("aisafe: uvx aisafe==$AISAFE_VERSION (pinned $AISAFE_VERSION)")
    } elseif (Get-Command pipx -ErrorAction SilentlyContinue) {
        [Console]::Error.WriteLine("aisafe: pipx aisafe==$AISAFE_VERSION (pinned $AISAFE_VERSION)")
    }
}

function Invoke-Aisafe {
    if (Get-Command aisafe -ErrorAction SilentlyContinue) {
        & aisafe @args
    } elseif (Get-Command uvx -ErrorAction SilentlyContinue) {
        & uvx --from "aisafe==$AISAFE_VERSION" aisafe @args
    } elseif (Get-Command pipx -ErrorAction SilentlyContinue) {
        & pipx run --spec "aisafe==$AISAFE_VERSION" aisafe @args
    } else {
        $global:LASTEXITCODE = 127
    }
}

# Summary counts from an evaluation report. `summary` is the first object carrying these
# keys (by_family comes after it), so the first match is the right one. Only `passed`
# means passed; none of the others is ever folded into it.
function Write-EvaluationSummary($path) {
    $text = Get-Content -Raw $path
    foreach ($key in @("sent", "passed", "failed", "missing", "errors", "skipped", "inconclusive", "observed")) {
        $m = [regex]::Match($text, "`"$key`"\s*:\s*([0-9]+)")
        $value = if ($m.Success) { $m.Groups[1].Value } else { "?" }
        Write-Output "evaluate ${key}: $value"
    }
    Write-Output "evaluate: only 'passed' means passed; failed, missing, errors, skipped, inconclusive and observed are separate"
}

# --- 3. aisafe evaluate, against an endpoint or over transcripts --------------
if (-not $url -and -not $transcripts) {
    Write-Output "evaluate: no endpoint or transcripts given (set AISAFE_EVALUATE_URL to a loopback URL you are authorised to test, or AISAFE_EVALUATE_TRANSCRIPTS to a JSONL file)"
    exit $status
}

if (-not (Test-Aisafe)) {
    [Console]::Error.WriteLine("evaluate skipped: aisafe not importable in target")
    exit $status
}

if ($transcripts) {
    Write-Output "evaluate: aisafe evaluate --transcripts $transcripts -o $evaluationReport"
    Write-Output "evaluate: transcripts are read locally; nothing is sent anywhere"
    if ($run -eq "1") {
        New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
        Write-WhichAisafe
        Invoke-Aisafe evaluate --transcripts $transcripts -o $evaluationReport @scriptArgs
        if ($LASTEXITCODE -ne 0) {
            [Console]::Error.WriteLine("evaluate: exited non-zero (1 = a tactic or an identity claim was observed, 2 = errors or unreadable input)")
            $status = 1
        }
        if (Test-Path $evaluationReport) {
            Write-EvaluationSummary $evaluationReport
        }
    } else {
        Write-Output "evaluate: not run (set AISAFE_EVALUATE_RUN=1 to run)"
    }
} else {
    Write-Output "evaluate: aisafe evaluate $url --families $families -o $evaluationReport"
    Write-Output "evaluate: a non-loopback target needs --i-have-authorization; this script never adds it, and nothing here is run against real users"
    if ($run -eq "1") {
        New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
        Write-WhichAisafe
        Invoke-Aisafe evaluate $url --families @familyList -o $evaluationReport @scriptArgs
        if ($LASTEXITCODE -ne 0) {
            [Console]::Error.WriteLine("evaluate: exited non-zero (1 = a scenario failed, 2 = errors/skipped/inconclusive present)")
            $status = 1
        }
        if (Test-Path $evaluationReport) {
            Write-EvaluationSummary $evaluationReport
        }
    } else {
        Write-Output "evaluate: not run (set AISAFE_EVALUATE_RUN=1 to run)"
    }
}

exit $status
