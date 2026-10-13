# Security policy

This policy applies to every public repository under [AZapata27](https://github.com/AZapata27)
that does not ship its own `SECURITY.md`.

## Supported versions

Only the **latest release** of each repository receives security fixes. Repositories without
releases are fixed on their default branch. Please upgrade before reporting.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion.**

1. Preferred: use **"Report a vulnerability"** in the repository's **Security** tab
   (GitHub private vulnerability reporting is enabled on all repositories).
2. Alternative: email **afzar27@gmail.com** with the subject `[security] <repository>`.

Please include the affected repository and version (tag or commit), a description of the
impact, and the steps or a proof of concept to reproduce it.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 7 days |
| Initial assessment (accepted / declined) | within 14 days |
| Fix or mitigation for accepted reports | as soon as practical, coordinated with you |

Fixes are published as a new release with a GitHub Security Advisory (and a CVE when it
applies). Reporters are credited unless they prefer otherwise. This is a personal,
best-effort project: there is no bug bounty.

## Scope

In scope: source code, build scripts, GitHub Actions workflows and published artifacts of
these repositories.

Out of scope: vulnerabilities in third-party dependencies with no demonstrated impact on
these projects (report them upstream), findings that only affect example or demo
configurations explicitly marked as not production-ready, and attacks against GitHub itself.
