---
name: fix-health-gap
description: >-
  Implements a single Repo Health Loop GitHub issue ([Health] title, health
  label) as a minimal PR. Use when an issue comment or automation asks to fix a
  health gap, or when Gap / Evidence / Suggested Fix sections are present.
---

# Fix Health Gap

Close one Critic-approved health issue with a focused PR. Do not expand scope.

## Inputs

Prefer the triggering GitHub issue. Extract:

1. **Gap** — what is missing or broken
2. **Evidence** — paths, HTTP status, missing sections
3. **Success Criterion Violated** — which rule from the health criteria
4. **Suggested Fix** — high-level direction only
5. **Priority** — Blocker / High / Medium / Low

If the issue body is incomplete, inspect the repo against
`.cursor/rules/repo-health.mdc` (or `SUCCESS_CRITERIA.md` when this skill pack
is present) before changing code.

## Workflow

1. **Confirm scope** — Fix only the stated gap. Skip “while I’m here” cleanups.
2. **Route by criterion** — Use a specialized skill when it fits:
   - Documentation UX → `update-readme-docs`
   - OpenSpec / Gherkin drift → `sync-openspec-gherkin`
   - Live deploy / HTTP failures → `vercel-health-check` (then fix)
3. **Implement the smallest change** that resolves the evidence.
4. **Verify** — Run the lightest check that proves the gap is gone (link check,
   `curl` for HTTP 200, open the README sections, run targeted tests if needed).
5. **Open a PR** that closes the issue (`Closes #N` / `Fixes #N`).
6. **PR description** — Gap addressed, criterion cited, what changed, how verified.

## Rules

- Prefer Medium / High / Blocker; abandon pure Low unless already in progress.
- Do not rewrite the whole project or invent new product features.
- Stack preference when creating new surface area: Svelte + FastAPI + SQLite/Redis
  + structured / OTEL-friendly logging. Document exceptions instead of silent drift.
- If blocked (missing secrets, private deploy access), comment on the issue with
  what is needed and stop — do not open an empty PR.

## Done when

- Evidence from the issue no longer holds
- PR links the issue and stays within the Suggested Fix intent
