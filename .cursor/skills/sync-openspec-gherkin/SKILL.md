---
name: sync-openspec-gherkin
description: >-
  Aligns OpenSpec (or equivalent) and Gherkin scenarios with the current
  implementation. Use when a [Health] issue reports outdated OpenSpec, missing
  Gherkin, spec drift from FastAPI routes or UI capabilities, or process/spec
  alignment gaps.
---

# Sync OpenSpec and Gherkin

Make specs and scenarios match what the code does today — not the ideal future.

## Locate artifacts

Search the repo for:

- OpenSpec / specs: `openspec/`, `specs/`, `docs/openspec/`, `AGENTS.md` pointers
- Gherkin: `*.feature`, `features/`, `e2e/`, `tests/**/*.feature`
- API truth: FastAPI routers, OpenAPI, primary UI routes

If the project uses a different but equivalent system, treat that as the spec
source of truth and say so in the PR.

## Workflow

1. **Inventory reality** — List current capabilities from code (routes, main UI flows).
2. **Diff against OpenSpec** — Mark stale, missing, or speculative sections.
3. **Update OpenSpec** so it describes current architecture and capabilities.
   - Prefer surgical edits over full rewrites.
   - Move unbuilt ideas to a clearly labeled “Planned” section or linked issues.
4. **Align Gherkin**
   - Add or update scenarios for core happy paths that already work.
   - Remove or tag `@wip` scenarios that assert unimplemented behavior.
   - Keep scenarios behavior-focused; avoid UI chrome trivia unless it is the bug.
5. **Beads / issues** — If the project uses Beads (`bd`), update or create tasks
   only when the health issue calls for tracking alignment; otherwise leave Beads alone.
6. **Verify** — Spec statements should be checkable against files/routes you cite
   in the PR.

## Rules

- Spec follows code for “today”; roadmap stays separate.
- Do not implement large missing features under the guise of syncing specs.
- One PR should leave OpenSpec + Gherkin mutually consistent for the touched area.
