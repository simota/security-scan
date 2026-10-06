# Engine map — the one place host tools are named

**Read when:** expert grade (`reference/expert-mode.md`), at E0 for the
preflights and whenever a spawn is written. No other file names a host tool,
binary or model; porting is an edit here.

## Spawning a worker

| Host (`expert.host`) | Spawn a worker with its own context | Collecting the return |
|---|---|---|
| `claude-code` | the `Agent` tool; `run_in_background: true` for parallel workers | completion notification; the worker also writes its return file |
| `codex` | `spawn_agent(prompt)` | `wait_agent(id)`; keep spawns foreground — a detached TTY can fail silently |
| `agy` | `/agent <name> "<task>"` in the TUI, or `agy -p "<prompt>" --dangerously-skip-permissions` headless | stdout is unreliable: have the worker write its return to an absolute path and read the file. Pass files as `@<path>` |

A second reply in the same context is not a worker. Every role in
`reference/expert-mode.md` needs a separate context.

## E0 spawn preflight (host)

Spawn one throwaway worker whose only job is to write `PREFLIGHT-OK` to
`<out>/run/preflight.txt`, then record the check. Delete a stale file first.

```
grep -qx PREFLIGHT-OK <out>/run/preflight.txt; echo "spawn preflight <host> exit=$?" >> <out>/run/gate.md
```

Exit 0 → `mode: full`. Anything else → `mode: single-agent`, which ends
`degraded`; the record keeps the exit code.

## E0 reachability preflight (each extra engine)

Only for engines the requester approved — an extra engine receives source
excerpts under another provider's terms.

```
codex exec "Reply with exactly ENGINE-OK." > <out>/run/engine-codex.txt 2>&1
grep -qx ENGINE-OK <out>/run/engine-codex.txt; echo "engine codex exit=$?" >> <out>/run/gate.md

agy -p "Reply with exactly ENGINE-OK." --dangerously-skip-permissions > <out>/run/engine-agy.txt 2>&1
grep -qx ENGINE-OK <out>/run/engine-agy.txt; echo "engine agy exit=$?" >> <out>/run/gate.md

claude -p "Reply with exactly ENGINE-OK." > <out>/run/engine-claude.txt 2>&1
grep -qx ENGINE-OK <out>/run/engine-claude.txt; echo "engine claude-code exit=$?" >> <out>/run/gate.md
```

An engine that fails is struck before E1; it is not discovered missing later.
Workers on an extra engine run headless with the same prompt files and write
their return to `run/spawns/`.

## Roles to tiers

Spawns name a tier, not a model: `high-reasoning` for verifiers, skeptics,
raters and QA; `balanced` for recon, discovery, variants, omission and
personas. Binding a tier to a model is the operator's choice, made here or not
at all; model names age faster than anything else in the skill.

## Spreading roles across engines

With more than one engine standing, the audit requires each discovery cell and
each refutation panel to span at least two engines. Put a skeptic on a
different engine from the finding's discoverers where the roster allows. With
one engine the report prints *single engine (declared)*; never present a
same-engine run as engine-diverse.
