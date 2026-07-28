---
name: vercel-health-check
description: >-
  Checks production or preview deploy health (Vercel or other live URLs): HTTP
  status, primary user flows, and obvious runtime failures. Use when a [Health]
  issue cites deploy failures, HTTP 5xx/4xx on live URLs, broken core paths, or
  functional success-criteria gaps.
---

# Vercel / Deploy Health Check

Prove whether the live app meets the functional health bar, then fix only what
the issue (or clear evidence) requires.

## Discover the URL

Prefer, in order:

1. URL stated in the GitHub issue evidence
2. README / docs production link
3. `vercel.json`, project settings notes, or deployment badges
4. `gh` / Vercel CLI only if already authenticated in the environment

Do not guess random hostnames.

## Checks

1. **HTTP** — `curl -sS -o /dev/null -w "%{http_code}"` on the primary URL.
   Expect 200 (or documented redirect to an OK page).
2. **Core paths** — Hit the main UI route and any `/api/health` (or equivalent)
   called out in the issue.
3. **Primary flow** — If browser tools are available, load the app and confirm
   the critical path named in the issue (not a full exploratory QA pass).
4. **Console / response errors** — Note obvious runtime failures tied to the gap.

Record exact status codes and URLs in the PR or issue comment.

## Fix path

- If the failure is in this repo (config, route, build, env example): fix it with
  the smallest change and describe how to verify on preview/production.
- If the failure needs dashboard secrets, DNS, or third-party access you lack:
  comment on the issue with evidence and stop.
- Add or repair a lightweight health endpoint only when the issue asks for it or
  the app has no better probe and the Suggested Fix points there.

## Rules

- Functional criterion: live URL OK **and** primary user flows work.
- Do not broaden into unrelated performance or SEO work.
- Prefer evidence over anecdotes (“works on my machine” is not enough).
