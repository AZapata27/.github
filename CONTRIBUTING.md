# Contributing

Thanks for your interest! This guide applies to every AZapata27 repository that does not
ship its own `CONTRIBUTING.md`.

## Before you start

- For anything non-trivial, open an issue first so we can agree on the approach.
- Security problems go through the [security policy](SECURITY.md), never a public issue.

## Pull request flow

1. Fork the repository (or create a branch if you have write access): `feat/…`, `fix/…`,
   `docs/…`, `chore/…`.
2. Make focused changes with tests. Build and test locally as described in the repository's
   `README.md`.
3. Open a pull request against the **default branch** and fill in the template.
4. **CI must be green.** The default branch is protected by a ruleset that requires the
   repository's CI checks and no new CodeQL alerts of high severity or above.
5. Pull requests are merged with **squash only**: the PR title becomes the commit message on
   the default branch.

## PR titles: Conventional Commits

The PR title must follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Easter-based holidays
fix(api): handle empty page token
docs: clarify setup steps
```

[release-please](https://github.com/googleapis/release-please) derives versions and the
changelog from these titles: `feat` → minor, `fix`/`perf` → patch, `!` or a
`BREAKING CHANGE:` footer → major. Other types (`docs`, `chore`, `ci`, `test`, `refactor`,
`build`) do not trigger a release.

## Signed commits

Every commit must be signed (SSH or GPG) and show as **Verified** on GitHub; the ruleset
rejects unsigned commits. See
[About commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification).

## GitHub Actions changes

Pin every action and reusable workflow to a full 40-character commit SHA with a version
comment (`uses: owner/action@<sha> # vX.Y.Z`) and keep job `permissions` minimal. The
repository settings reject workflows that use unpinned actions.

## Code of conduct

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
