# .github

Two things for every public repository under [AZapata27](https://github.com/AZapata27):

1. **Default community health files.** GitHub uses them for any repository of this account
   that does not have its own: [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md),
   [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [SUPPORT.md](SUPPORT.md), issue forms and the
   pull request template under [.github/](.github).
2. **Policy as code** for repository protections: branch/tag rulesets, security features and
   GitHub Actions settings, described in [policies/](policies) and enforced by
   [scripts/policy.py](scripts/policy.py) (Python standard library + `gh api`).

### Why not organization rulesets?

Rulesets that target many repositories at once are an organization feature that needs
GitHub Team or Enterprise
([Creating rulesets for repositories in your organization](https://docs.github.com/en/organizations/managing-organization-settings/creating-rulesets-for-repositories-in-your-organization)).
A personal account only has per-repository rulesets
([About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)).
This repository keeps one template and pushes it to each repository, so the rules stay
identical and reviewable in Git.

## What is enforced

| Rule / setting | Why |
|---|---|
| Ruleset `protect-default-branch` on `~DEFAULT_BRANCH`, active | One definition that survives branch renames |
| Block deletion and force pushes | History on the default branch is never rewritten or lost |
| Linear history, squash merge only | One commit per PR whose message is the Conventional Commit title release-please reads |
| Signed commits required | Every commit on the default branch is attributable (Verified) |
| Pull request required (0 approvals, stale reviews dismissed) | Every change goes through CI; a solo maintainer cannot approve their own PRs |
| Required status checks (per repo, GitHub Actions app) | Lint, build/tests and dependency review must pass before merging |
| Code scanning: CodeQL, security alerts `high_or_higher`, alerts `errors` | Blocks merges that introduce serious CodeQL findings. Scorecard is not included: its alerts are process findings and would block every PR |
| Admin bypass only via pull request | The owner can merge a PR in an emergency, but never push directly |
| Ruleset `protect-release-tags` (`refs/tags/v*`), opt-in per repo | Published versions cannot be moved or deleted (used by `reusable-workflows`, whose consumers pin them) |
| Actions: all actions allowed, **SHA pinning required** | Third-party code cannot change under us; a workflow using an unpinned action fails |
| Workflow token read-only by default; Actions may approve PRs | Least privilege; release-please needs to open and approve its release PRs |
| Secret scanning + push protection | Leaked credentials are blocked at push time |
| Dependabot alerts + security updates | Vulnerable dependencies are reported and patched automatically |
| Private vulnerability reporting | Matches [SECURITY.md](SECURITY.md): reports arrive privately |
| Immutable releases | Release assets and tags cannot be altered after publishing |

## Baseline practices we follow

- Every action and reusable workflow is pinned to a full commit SHA (`@<sha> # vX.Y.Z`);
  Dependabot bumps them weekly, grouped, with a 7-day cooldown.
- `permissions: {}` at workflow level and minimal per-job permissions; no admin tokens or
  long-lived secrets stored in Actions.
- Protected default branch with required checks whose names match real CI jobs.
- Signed commits, squash merges and Conventional Commit PR titles; versions and changelogs by
  release-please.
- Secret scanning with push protection on every repository.
- CodeQL on every PR plus a weekly run; OpenSSF Scorecard on a schedule.
- Immutable releases, with build provenance attestations where artifacts are published.
- Private vulnerability reporting and a single security policy.
- Shared CI logic in [reusable-workflows](https://github.com/AZapata27/reusable-workflows),
  consumed by SHA.
- `step-security/harden-runner` on every job (egress audit).

## Deliberately NOT doing (and when to reconsider)

| Not doing | Why | Reconsider when |
|---|---|---|
| Required approvals | Solo maintainer: nobody else can approve | A second maintainer joins |
| safe-settings, Terraform or Probot apps | Overkill for fewer than 20 repositories; one script is enough | More than ~20 repos or several owners |
| Organization migration | A personal account is enough for public solo projects | Collaborators join or private repositories need rulesets |
| Self-hosted runners | Cost and attack surface for no gain | Workloads need special hardware or private networks |
| GitHub App for releases | release-please works with `GITHUB_TOKEN`; merges use the admin pull-request bypass | Admin-bypass merges become annoying, or release PRs must trigger CI |
| Scorecard as a code scanning merge gate | Its findings are about process, not code, and would block merges | Never as a gate; track the score instead |
| Merge queue, deployment rules, CODEOWNERS | No concurrency or reviewers to route | Traffic or team size grows |

## How to

Requirements: Python 3.10+ and the [GitHub CLI](https://cli.github.com/) logged in as the
owner (`gh auth status`). Full-scope `plan`, `audit` and `apply` need repository admin.

```bash
python -I scripts/policy.py validate          # policy files only, no network
python -I scripts/policy.py plan              # read-only diff desired vs live (default command)
python -I scripts/policy.py apply             # create/update what drifted (idempotent)
python -I scripts/policy.py audit             # like plan, exit 1 on drift
python -I scripts/policy.py plan --repo grpc-examples   # limit to one or more repos
```

**Add a new repository.** Let its CI run once on a PR, then append an entry to
[policies/repos.json](policies/repos.json) with `name`, `default_branch` and
`required_checks` (plus `"release_tags": true` if it publishes `v*` tags). Run `plan`, then
`apply`. Before SHA pinning is enforced, every `uses:` in the repository must point to a
40-character SHA (local `./` references are fine), or its runs will fail. Per-repository
exceptions go in an optional `settings` object that overrides
[policies/repo-settings.json](policies/repo-settings.json), e.g.
`"settings": {"actions_permissions": {"sha_pinning_required": false}}`; a repository that
does not run CodeQL must set `"code_scanning": false`, or its PRs wait for CodeQL results
forever.

**Change a required check.** Edit `required_checks` for that repository, `plan`, `apply`.
Check names must match the real check run names exactly (for reusable workflows:
`<caller job name> / <called job name>`, as shown in a PR's checks tab). A name that never
reports blocks every merge.

**Audit.** The [Policy audit](.github/workflows/audit.yml) workflow runs weekly (and on
demand) with a read-only `GITHUB_TOKEN`: `audit --scope public` compares rulesets and the
rules active on each default branch. Bypass actors, Actions permissions and
`security_and_analysis` are not readable without admin, so audit them locally as the owner:

```bash
python -I scripts/policy.py audit             # full scope
```

No admin token is stored anywhere.

## License

[Apache-2.0](LICENSE)
