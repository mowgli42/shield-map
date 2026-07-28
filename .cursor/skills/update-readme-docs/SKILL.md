---
name: update-readme-docs
description: >-
  Restructures or completes a project README to the Repo Health documentation
  UX order: summary, screenshots, architecture diagram, sequence diagrams,
  remaining capabilities. Use when a [Health] issue cites documentation UX,
  missing screenshots, missing diagrams, or wall-of-text READMEs.
---

# Update README Docs

Bring the primary README (or docs landing page) to the health-loop documentation order.

## Required order

1. Short, friendly summary of what the project does **today**
2. Screenshot(s) of the current UI / key screens
3. Architecture diagram
4. Sequence diagram(s) for the most important flows
5. Remaining / planned capabilities

Wall-of-text first is not acceptable. Move long history, migration notes, and deep
internals below these sections (or into linked docs).

## Workflow

1. Read the current README and note which of the five sections exist.
2. Write or rewrite the **summary** in plain language (what works now, not the roadmap).
3. **Screenshots**
   - Prefer existing images under `docs/`, `assets/`, or similar.
   - If none exist and you can run the UI locally, capture key screens and commit
     them under a sensible path (e.g. `docs/images/`).
   - If you cannot capture screenshots, add clearly marked placeholders with the
     exact screens needed and note that in the PR — do not fake images.
4. **Architecture diagram** — Mermaid in the README is preferred when it stays accurate.
5. **Sequence diagram(s)** — Cover the primary user or request flow only.
6. **Remaining / planned** — Short bullet list; link issues when they exist.
7. Fix broken relative links you touch; do not boil the ocean on unrelated docs.

## Rules

- Keep the top of the README scannable on mobile.
- Do not replace product truth with aspirational marketing.
- If OpenSpec or architecture docs already exist, link them from the diagram
  section instead of duplicating large specs.
