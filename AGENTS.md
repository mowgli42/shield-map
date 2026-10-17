# shield-map

User CLIs: `shield-map`, `shield-up`, `shield-audit` (Python package import remains `fw_audit`).
Ingests netstat/ss or an init questionnaire, classifies listeners, emits deny-by-default firewall rules plus XML/HTML audit reports; Linux harden via `shield-up`.
Stack: Python 3.10+, Typer, PyYAML. No Svelte/FastAPI UI — CLI + XSLT HTML is the product surface.
Posture: ponytail (repo created 2025-12-24). Shared health pack: `.cursor/skills/` and `.cursor/rules/`.

## Commands

- Setup: `python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"`
- Test: `.venv/bin/python -m pytest tests/ -q`
- Lint: `.venv/bin/ruff check src tests`
- Demo: `./shield-map --input examples/dmz-lab/imports --hosts examples/dmz-lab/hosts.yaml -o out/ --platform all`
- Harden: `./shield-up -o out-harden/`
- Drift: `./shield-audit -b out/audit-report.xml -o /tmp/drift`
- Init demo: `fw-audit init --answers examples/home-lab/init-answers-client.yaml -o out-init/`
- Secrets: `bash scripts/scan-secrets.sh .`

## Hard prohibitions

- Do not commit private keys, `*-key.pem`, `*.key`, `.env` secrets, or `BEGIN … PRIVATE KEY`. Generate locally; gitignore keys.
- Do not apply generated rulesets to a live host without review. Emit to `out/` and leave apply to the operator.
- Do not invent CLI flags, platforms, or library exports. Public surface is `shield-map` / `shield-up` / `shield-audit` plus library `analyze` / `diff` / `generate_local_only`.
- Do not rewrite OpenSpec / Gherkin / Beads to match a hoped-for future (cloud generators, nmap). Update specs only after code shipped.
- Do not scrape CLI stdout as the SnarkSentinel contract. Use the library API in `docs/INTEGRATION.md`.

## Verify by change type

| Change | Check |
| --- | --- |
| CLI / parser / classify / generate | `pytest` on the touched test module; run the matching `features/*.feature` happy path by hand if the contract changed |
| Library API | `from fw_audit import analyze, diff, generate_local_only` still matches `docs/INTEGRATION.md` and `features/library-api.feature` |
| Spec | `openspec/spec.md` capability still true; matching `.feature` updated |
| Report / XSLT | generate XML then `fw-audit html` if `xsltproc` is available |
| Secrets | `bash scripts/scan-secrets.sh .` passes |

## Source of truth

- Behavior: `openspec/spec.md` + `features/*.feature`
- Remaining work: Beads (`.beads/`) / GitHub issues
- Sample outputs: `docs/examples/`
- Health bar: do not duplicate SUCCESS_CRITERIA.md here

## House vocabulary

- preferred / risky / unsafe — listener categories. Do not invent “critical port” as a fourth bucket.
- zone / allowed_zone_pairs — multi-host graph language in `hosts.yaml`.
- all-in-one — the batch CLI, not a separate product.
- init profile — Phase 1a questionnaire answers YAML, not netstat ingest.

## Good / bad

Bad: treating `docs/PLAN.md` Phase 3–4 cloud generators as shipped.
Good: keep Planned items in OpenSpec Planned; only document parsers, classify, generators, diff, and library API that exist under `src/fw_audit/`.

## Borrowed patterns

- Hard prohibitions from ossrules.md `hard-prohibition` — review-before-apply and no invented CLI.
- Verification by change type from ossrules.md `verification-matrix`.
- Pointing at the source of truth from ossrules.md `single-source`.
- House vocabulary from ossrules.md `house-vocabulary`.
