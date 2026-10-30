# Architecture

Two diagrams: what the package is made of, and what one audit does. Both are drawn from
the code as it is after the pivot (2026-10-29); the paths are real.

## The package

```mermaid
flowchart LR
    subgraph policy["policy/ (versioned)"]
        CH["charter.md"]
        ME["mechanisms.yaml<br/>M1..M8, decisions,<br/>severity criteria"]
    end
    subgraph src["src/aisafe/"]
        CLI["cli.py<br/>audit | review | evaluate | fleet | skill"]
        AUD["audit.py<br/>the run"]
        DISC["discovery/<br/>walk, patterns, vocabulary,<br/>discover, configs"]
        ANA["analysis/<br/>pydeep, checks, flows"]
        EVI["evidence/<br/>model, artifacts"]
        RUL["rules/<br/>profiling, influence, identity,<br/>controls, review"]
        REV["review/<br/>records, baseline"]
        REP["reporting/<br/>terminal, json, markdown,<br/>sarif, html"]
        EVAL["evaluation/<br/>scenarios + corpus"]
        SK["skills/ai-safety-audit/<br/>agent workflow"]
    end
    ME -->|load_policy| RUL
    ME --> REP
    CLI --> AUD
    CLI --> REV
    CLI --> EVAL
    AUD --> DISC --> ANA --> RUL --> REP
    DISC --> EVI
    ANA --> EVI
    RUL --> EVI
    REV --> AUD
    EVAL -.->|evaluation-report.json<br/>read as observed behaviour| DISC
    SK -.->|runs the commands| CLI
```

- `policy/` is definitions: what the mechanisms are and what words a finding may use.
- `discovery/` finds surfaces: prompt files, prompt literals and assemblies, model calls,
  ingress, memory stores, personas, the person signals.
- `analysis/` connects them: the prompt-to-call link in Python, the native checks that
  replaced the retired linters, the chain `objective -> person data -> inference -> prompt
  -> intervention -> feedback` with each link's status.
- `evidence/` is the shared vocabulary: findings, evidence status, decision, control
  status, artifact hashes, redaction, fingerprints.
- `rules/` decides: ten rules, each serving one mechanism of the policy.
- `review/` holds the human decisions: the review record bound to artifact hashes and
  the baseline of accepted findings, both carrying the policy version.
- `reporting/` renders, in five formats, without ever producing a single score.
- `evaluation/` is separate and explicit: scripted scenarios against an endpoint the
  operator is authorised to test, or supplied transcripts; never real users.

## One audit

```mermaid
flowchart TD
    A["aisafe audit PATH"] --> W["walk<br/>files, units, .gitignore,<br/>own output skipped"]
    W --> D["discover<br/>pattern pass: model calls, prompts,<br/>ingress, person signals, memory,<br/>personas, review records, evaluation reports"]
    D --> P["pydeep (Python)<br/>prompt literals, assemblies,<br/>call sites, reply path"]
    P --> C["checks<br/>native checks over Python text"]
    C --> F["flows<br/>chain per prompt, link status:<br/>ast | declared | co-located;<br/>trace against the policy pattern"]
    F --> R["rules<br/>AUD-1101..1110<br/>evidence status + policy decision"]
    R --> B["baseline<br/>new | unchanged | re-review<br/>(policy version compared)"]
    B --> O["report<br/>mechanism coverage, findings,<br/>UNKNOWN, inventory"]
    O --> X{"exit code"}
    X -->|"0"| X0["nothing counted<br/>(not a certification)"]
    X -->|"1"| X1["a finding at or above --fail-on,<br/>or an UNKNOWN under --fail-on-unknown"]
    X -->|"2"| X2["fatal"]
    D -. "coverage gaps:<br/>unsupported language, remote prompt,<br/>opaque model, no runtime config" .-> O
```

The run opens no network socket, calls no model and installs nothing. The two optional
inputs it reads from the tree are documents a person produced earlier: the review record
(`aisafe review`) and an evaluation report (`aisafe evaluate`).

## The agent workflow (skill)

```mermaid
sequenceDiagram
    participant U as Person
    participant Ag as Agent (skill)
    participant T as aisafe
    Ag->>T: audit . --format json --write-baseline
    T-->>Ag: findings by mechanism, UNKNOWN, coverage
    Ag->>T: audit . --format html
    Ag->>U: walk the mechanisms: evidence vs decision vs unknown
    U->>Ag: contextual decisions, declared purpose
    Ag->>T: review record --reviewer "<person>" --purpose ...
    loop one change per approval
        Ag->>U: a diff that removes the objective, inference or intervention
        U-->>Ag: yes / defer / accept with a reason
        Ag->>T: audit . --baseline ... (re-check)
    end
    opt with approval, authorised endpoint or transcripts
        Ag->>T: evaluate <loopback-url> --families crisis_disclosure goodbye_pressure
        T-->>Ag: evaluation-report.json (observed behaviour)
    end
```

The agent's reading is attributed (`assisted_by`) and never recorded as the reviewer.
