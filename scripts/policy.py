#!/usr/bin/env python3
"""Policy as code for AZapata27 repositories: rulesets, security and Actions settings.

Desired state lives in ../policies/*.json. Live state is read and written with `gh api`
(GitHub CLI), so authentication is whatever `gh` uses (keyring login or GH_TOKEN).
Standard library only.

Subcommands:
  validate  Check the policy files (structure, enums, duplicates). No network.
  plan      Read-only diff between desired and live state (default).
  apply     Create/update whatever drifted. Idempotent. Needs repository admin.
  audit     Like plan, but exits 1 on drift (for CI).

Scopes (plan/audit):
  full    Rulesets (incl. bypass actors) + security/Actions settings. Needs repository admin.
  public  Only what a read-only token can see on public repos: rulesets without bypass
          actors, plus the rules actually active on each default branch.

Examples:
  python -I scripts/policy.py validate
  python -I scripts/policy.py plan
  python -I scripts/policy.py plan --repo grpc-examples
  python -I scripts/policy.py apply --repo grpc-examples
  python -I scripts/policy.py audit --scope public
"""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICIES = ROOT / "policies"
GITHUB_ACTIONS_APP_ID = 15368  # integration_id of the "GitHub Actions" app for required checks

KNOWN_RULE_TYPES = {
    "creation", "update", "deletion", "required_linear_history", "merge_queue",
    "required_deployments", "required_signatures", "pull_request", "required_status_checks",
    "non_fast_forward", "commit_message_pattern", "commit_author_email_pattern",
    "committer_email_pattern", "branch_name_pattern", "tag_name_pattern", "file_path_restriction",
    "max_file_path_length", "file_extension_restriction", "max_file_size", "workflows",
    "code_scanning", "copilot_code_review",
}
ALERTS_THRESHOLDS = {"none", "errors", "errors_and_warnings", "all"}
SECURITY_ALERTS_THRESHOLDS = {"none", "critical", "high_or_higher", "medium_or_higher", "all"}
SECURITY_AND_ANALYSIS_KEYS = {
    "advanced_security", "code_security", "secret_scanning", "secret_scanning_push_protection",
    "secret_scanning_non_provider_patterns", "secret_scanning_validity_checks",
    "secret_scanning_ai_detection", "dependabot_security_updates",
}
REPO_KEYS = {"name", "default_branch", "required_checks", "release_tags",
             "protect_default_branch", "code_scanning", "settings", "note"}
SETTINGS_KEYS = {"vulnerability_alerts", "private_vulnerability_reporting", "immutable_releases",
                 "security_and_analysis", "actions_permissions", "workflow_permissions"}


# --------------------------------------------------------------------------- gh api


class ApiError(RuntimeError):
    def __init__(self, status: int, path: str, detail: str):
        super().__init__(f"HTTP {status} on {path}: {detail}")
        self.status = status


def gh(method: str, path: str, body: object | None = None) -> tuple[int, object | None]:
    """Call `gh api` and return (status, parsed JSON body or None). Raises on non-2xx."""
    exe = shutil.which("gh")
    if not exe:
        sys.exit("error: GitHub CLI 'gh' not found in PATH")
    cmd = [exe, "api", "--include", "--method", method,
           "-H", "Accept: application/vnd.github+json",
           "-H", "X-GitHub-Api-Version: 2022-11-28", path]
    data = None
    if body is not None:
        cmd += ["--input", "-"]
        data = json.dumps(body)
    proc = subprocess.run(cmd, input=data, capture_output=True, text=True, encoding="utf-8")
    out = proc.stdout.replace("\r\n", "\n")
    head, _, payload = out.partition("\n\n")
    try:
        status = int(head.split("\n", 1)[0].split()[1])
    except (IndexError, ValueError):
        raise ApiError(0, path, (proc.stderr or out).strip()) from None
    parsed = None
    if payload.strip():
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            parsed = payload.strip()
    if status >= 300:
        msg = parsed.get("message") if isinstance(parsed, dict) else (proc.stderr or "").strip()
        raise ApiError(status, path, str(msg))
    return status, parsed


def gh_get_or_none(path: str) -> tuple[int, object | None] | None:
    try:
        return gh("GET", path)
    except ApiError as exc:
        if exc.status == 404:
            return None
        raise


# --------------------------------------------------------------------------- config


def load_json(name: str) -> dict:
    with open(POLICIES / name, encoding="utf-8") as fh:
        return json.load(fh)


def load_config() -> dict:
    return {
        "repos": load_json("repos.json"),
        "default_branch": load_json("ruleset-default-branch.json"),
        "release_tags": load_json("ruleset-release-tags.json"),
        "settings": load_json("repo-settings.json"),
    }


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def desired_state(cfg: dict, repo: dict) -> dict:
    rulesets = []
    if repo.get("protect_default_branch", True):
        rs = copy.deepcopy(cfg["default_branch"])
        if repo.get("code_scanning", True) is False:
            rs["rules"] = [r for r in rs["rules"] if r["type"] != "code_scanning"]
        for rule in rs["rules"]:
            if rule["type"] == "required_status_checks":
                rule["parameters"]["required_status_checks"] = [
                    {"context": c, "integration_id": GITHUB_ACTIONS_APP_ID}
                    for c in repo["required_checks"]
                ]
        rulesets.append(rs)
    if repo.get("release_tags", False):
        rulesets.append(copy.deepcopy(cfg["release_tags"]))
    return {
        "rulesets": rulesets,
        "settings": deep_merge(cfg["settings"], repo.get("settings", {})),
    }


# --------------------------------------------------------------------------- validate


def validate(cfg: dict) -> list[str]:
    errors: list[str] = []
    repos_cfg = cfg["repos"]
    if not isinstance(repos_cfg.get("owner"), str) or not repos_cfg["owner"]:
        errors.append("repos.json: 'owner' must be a non-empty string")
    repos = repos_cfg.get("repos")
    if not isinstance(repos, list) or not repos:
        errors.append("repos.json: 'repos' must be a non-empty list")
        repos = []
    seen: set[str] = set()
    for i, repo in enumerate(repos):
        where = f"repos.json: repos[{i}]"
        if not isinstance(repo, dict):
            errors.append(f"{where}: must be an object")
            continue
        name = repo.get("name")
        where = f"repos.json: {name or f'repos[{i}]'}"
        if not isinstance(name, str) or not name:
            errors.append(f"{where}: 'name' must be a non-empty string")
        elif name.lower() in seen:
            errors.append(f"{where}: duplicated repository")
        else:
            seen.add(name.lower())
        unknown = set(repo) - REPO_KEYS
        if unknown:
            errors.append(f"{where}: unknown keys {sorted(unknown)}")
        if not isinstance(repo.get("default_branch"), str) or not repo.get("default_branch"):
            errors.append(f"{where}: 'default_branch' must be a non-empty string")
        checks = repo.get("required_checks")
        if not isinstance(checks, list) or not all(isinstance(c, str) and c.strip() for c in checks):
            errors.append(f"{where}: 'required_checks' must be a list of non-empty strings")
        else:
            if len(set(checks)) != len(checks):
                errors.append(f"{where}: duplicated required check")
            if repo.get("protect_default_branch", True) and not checks:
                errors.append(f"{where}: protected default branch needs at least one required check")
        for flag in ("release_tags", "protect_default_branch", "code_scanning"):
            if flag in repo and not isinstance(repo[flag], bool):
                errors.append(f"{where}: '{flag}' must be a boolean")
        if "settings" in repo:
            errors += validate_settings(repo["settings"], f"{where}.settings", partial=True)

    for key, fname, target in (("default_branch", "ruleset-default-branch.json", "branch"),
                               ("release_tags", "ruleset-release-tags.json", "tag")):
        errors += validate_ruleset(cfg[key], fname, target)
    types = {r.get("type") for r in cfg["default_branch"].get("rules", [])}
    if "required_status_checks" not in types:
        errors.append("ruleset-default-branch.json: must contain a required_status_checks rule")
    errors += validate_settings(cfg["settings"], "repo-settings.json", partial=False)
    return errors


def validate_ruleset(rs: dict, where: str, target: str) -> list[str]:
    errors = []
    if not isinstance(rs.get("name"), str) or not rs.get("name"):
        errors.append(f"{where}: 'name' must be a non-empty string")
    if rs.get("target") != target:
        errors.append(f"{where}: 'target' must be '{target}'")
    if rs.get("enforcement") not in {"active", "evaluate", "disabled"}:
        errors.append(f"{where}: invalid 'enforcement'")
    include = rs.get("conditions", {}).get("ref_name", {}).get("include")
    if not isinstance(include, list) or not include:
        errors.append(f"{where}: conditions.ref_name.include must be a non-empty list")
    for actor in rs.get("bypass_actors", []):
        if not {"actor_id", "actor_type", "bypass_mode"} <= set(actor):
            errors.append(f"{where}: bypass actor needs actor_id, actor_type and bypass_mode")
    rules = rs.get("rules")
    if not isinstance(rules, list) or not rules:
        return errors + [f"{where}: 'rules' must be a non-empty list"]
    seen = set()
    for rule in rules:
        rtype = rule.get("type")
        if rtype not in KNOWN_RULE_TYPES:
            errors.append(f"{where}: unknown rule type {rtype!r}")
        if rtype in seen:
            errors.append(f"{where}: duplicated rule {rtype!r}")
        seen.add(rtype)
        if rtype == "code_scanning":
            tools = rule.get("parameters", {}).get("code_scanning_tools")
            if not isinstance(tools, list) or not tools:
                errors.append(f"{where}: code_scanning needs parameters.code_scanning_tools")
                continue
            for tool in tools:
                if not tool.get("tool"):
                    errors.append(f"{where}: code_scanning tool without 'tool'")
                if tool.get("alerts_threshold") not in ALERTS_THRESHOLDS:
                    errors.append(f"{where}: invalid alerts_threshold {tool.get('alerts_threshold')!r}")
                if tool.get("security_alerts_threshold") not in SECURITY_ALERTS_THRESHOLDS:
                    errors.append(f"{where}: invalid security_alerts_threshold "
                                  f"{tool.get('security_alerts_threshold')!r}")
        if rtype == "pull_request":
            methods = rule.get("parameters", {}).get("allowed_merge_methods", [])
            if not set(methods) <= {"merge", "squash", "rebase"}:
                errors.append(f"{where}: invalid allowed_merge_methods {methods}")
    return errors


def validate_settings(s: dict, where: str, partial: bool) -> list[str]:
    errors = []
    if not isinstance(s, dict):
        return [f"{where}: must be an object"]
    unknown = set(s) - SETTINGS_KEYS
    if unknown:
        errors.append(f"{where}: unknown keys {sorted(unknown)}")
    if not partial:
        missing = SETTINGS_KEYS - set(s)
        if missing:
            errors.append(f"{where}: missing keys {sorted(missing)}")
    for key in ("vulnerability_alerts", "private_vulnerability_reporting", "immutable_releases"):
        if key in s and not isinstance(s[key], bool):
            errors.append(f"{where}.{key}: must be a boolean")
    for key, value in s.get("security_and_analysis", {}).items():
        if key not in SECURITY_AND_ANALYSIS_KEYS:
            errors.append(f"{where}.security_and_analysis: unknown feature {key!r}")
        if value not in {"enabled", "disabled"}:
            errors.append(f"{where}.security_and_analysis.{key}: must be 'enabled' or 'disabled'")
    ap = s.get("actions_permissions", {})
    if "allowed_actions" in ap and ap["allowed_actions"] not in {"all", "local_only", "selected"}:
        errors.append(f"{where}.actions_permissions.allowed_actions: invalid value")
    for key in ("enabled", "sha_pinning_required"):
        if key in ap and not isinstance(ap[key], bool):
            errors.append(f"{where}.actions_permissions.{key}: must be a boolean")
    wp = s.get("workflow_permissions", {})
    if "default_workflow_permissions" in wp and wp["default_workflow_permissions"] not in {"read", "write"}:
        errors.append(f"{where}.workflow_permissions.default_workflow_permissions: invalid value")
    if "can_approve_pull_request_reviews" in wp and not isinstance(wp["can_approve_pull_request_reviews"], bool):
        errors.append(f"{where}.workflow_permissions.can_approve_pull_request_reviews: must be a boolean")
    return errors


# --------------------------------------------------------------------------- diff


def _norm(value: object) -> object:
    """Order-insensitive normal form for lists inside rules and conditions."""
    if isinstance(value, dict):
        return {k: _norm(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        items = [_norm(v) for v in value]
        return sorted(items, key=lambda v: json.dumps(v, sort_keys=True))
    return value


def diff_ruleset(desired: dict, live: dict, scope: str) -> list[str]:
    out = []
    for key in ("target", "enforcement"):
        if live.get(key) != desired[key]:
            out.append(f"{key}: {live.get(key)!r} -> {desired[key]!r}")
    if _norm(live.get("conditions")) != _norm(desired["conditions"]):
        out.append(f"conditions: {json.dumps(live.get('conditions'))} -> {json.dumps(desired['conditions'])}")
    if scope == "full" and "bypass_actors" in live:
        keys = ("actor_id", "actor_type", "bypass_mode")
        lv = _norm([{k: a.get(k) for k in keys} for a in live["bypass_actors"]])
        dv = _norm([{k: a.get(k) for k in keys} for a in desired["bypass_actors"]])
        if lv != dv:
            out.append(f"bypass_actors: {json.dumps(lv)} -> {json.dumps(dv)}")
    live_rules = {r["type"]: r.get("parameters", {}) for r in live.get("rules", [])}
    want_rules = {r["type"]: r.get("parameters", {}) for r in desired["rules"]}
    for rtype in sorted(set(want_rules) - set(live_rules)):
        out.append(f"rule {rtype}: missing -> add")
    for rtype in sorted(set(live_rules) - set(want_rules)):
        out.append(f"rule {rtype}: not in policy -> remove")
    for rtype in sorted(set(want_rules) & set(live_rules)):
        for key, want in want_rules[rtype].items():
            have = live_rules[rtype].get(key)
            if _norm(have) == _norm(want):
                continue
            if rtype == "required_status_checks" and key == "required_status_checks":
                have_c = {c["context"] for c in have or []}
                want_c = {c["context"] for c in want}
                for c in sorted(want_c - have_c):
                    out.append(f"rule required_status_checks: + {c!r}")
                for c in sorted(have_c - want_c):
                    out.append(f"rule required_status_checks: - {c!r}")
                if have_c == want_c:
                    out.append("rule required_status_checks: integration_id differs")
            else:
                out.append(f"rule {rtype}.{key}: {json.dumps(have)} -> {json.dumps(want)}")
    return out


def read_rulesets(owner: str, name: str, desired: list[dict]) -> dict[str, dict | None]:
    _, listing = gh("GET", f"repos/{owner}/{name}/rulesets?includes_parents=false&per_page=100")
    by_name = {r["name"]: r["id"] for r in listing or []}
    live = {}
    for rs in desired:
        rid = by_name.get(rs["name"])
        live[rs["name"]] = gh("GET", f"repos/{owner}/{name}/rulesets/{rid}")[1] if rid else None
    return live


def read_settings(owner: str, name: str) -> dict:
    base = f"repos/{owner}/{name}"
    _, repo = gh("GET", base)
    sa = {k: v.get("status") for k, v in (repo.get("security_and_analysis") or {}).items()}
    pvr = gh_get_or_none(f"{base}/private-vulnerability-reporting")
    imm = gh_get_or_none(f"{base}/immutable-releases")
    return {
        "vulnerability_alerts": gh_get_or_none(f"{base}/vulnerability-alerts") is not None,
        "private_vulnerability_reporting": bool(pvr and pvr[1].get("enabled")),
        "immutable_releases": bool(imm and imm[1].get("enabled")),
        "security_and_analysis": sa,
        "actions_permissions": gh("GET", f"{base}/actions/permissions")[1],
        "workflow_permissions": gh("GET", f"{base}/actions/permissions/workflow")[1],
    }


def diff_settings(desired: dict, live: dict) -> list[str]:
    out = []
    for key in ("vulnerability_alerts", "private_vulnerability_reporting", "immutable_releases"):
        if key in desired and live[key] != desired[key]:
            out.append(f"{key}: {live[key]} -> {desired[key]}")
    for group in ("security_and_analysis", "actions_permissions", "workflow_permissions"):
        for key, want in desired.get(group, {}).items():
            have = live[group].get(key)
            if have != want:
                out.append(f"{group}.{key}: {json.dumps(have)} -> {json.dumps(want)}")
    return out


def plan_repo(cfg: dict, owner: str, repo: dict, scope: str) -> dict:
    name = repo["name"]
    want = desired_state(cfg, repo)
    result = {"name": name, "rulesets": {}, "settings": [], "live_rulesets": {}, "branch_rules": []}
    live_rs = read_rulesets(owner, name, want["rulesets"])
    result["live_rulesets"] = live_rs
    for rs in want["rulesets"]:
        live = live_rs[rs["name"]]
        result["rulesets"][rs["name"]] = (["ruleset missing -> create"] if live is None
                                          else diff_ruleset(rs, live, scope))
    if scope == "public":
        # Cross-check what GitHub actually enforces on the default branch.
        default_rs = next((rs for rs in want["rulesets"] if rs["target"] == "branch"), None)
        if default_rs and live_rs.get(default_rs["name"]):
            rid = live_rs[default_rs["name"]]["id"]
            _, active = gh("GET", f"repos/{owner}/{name}/rules/branches/{repo['default_branch']}?per_page=100")
            active_types = {r["type"] for r in active or [] if r.get("ruleset_id") == rid}
            for rule in default_rs["rules"]:
                if rule["type"] not in active_types:
                    result["branch_rules"].append(
                        f"rule {rule['type']} not active on branch {repo['default_branch']!r}")
    else:
        result["settings"] = diff_settings(want["settings"], read_settings(owner, name))
    return result


def has_drift(result: dict) -> bool:
    return bool(result["settings"] or result["branch_rules"] or any(result["rulesets"].values()))


def print_plan(result: dict) -> None:
    status = "drift" if has_drift(result) else "in sync"
    print(f"\n== {result['name']}: {status}")
    for rs_name, changes in result["rulesets"].items():
        for change in changes:
            print(f"  ~ ruleset {rs_name}: {change}")
    for change in result["branch_rules"]:
        print(f"  ~ {change}")
    for change in result["settings"]:
        print(f"  ~ {change}")


# --------------------------------------------------------------------------- apply


def apply_repo(cfg: dict, owner: str, repo: dict, dry: dict) -> list[str]:
    name, base = repo["name"], f"repos/{owner}/{repo['name']}"
    want = desired_state(cfg, repo)
    s = want["settings"]
    done = []
    changed = {line.split(":", 1)[0].split(".", 1)[0] for line in dry["settings"]}

    toggles = (("vulnerability_alerts", "vulnerability-alerts"),
               ("private_vulnerability_reporting", "private-vulnerability-reporting"),
               ("immutable_releases", "immutable-releases"))
    for key, endpoint in toggles[:1]:  # alerts first: Dependabot security updates depend on them
        if key in changed:
            gh("PUT" if s[key] else "DELETE", f"{base}/{endpoint}")
            done.append(f"{key} -> {s[key]}")
    if "security_and_analysis" in changed:
        body = {"security_and_analysis": {k: {"status": v} for k, v in s["security_and_analysis"].items()}}
        gh("PATCH", base, body)
        done.append(f"security_and_analysis -> {json.dumps(s['security_and_analysis'])}")
    for key, endpoint in toggles[1:]:
        if key in changed:
            gh("PUT" if s[key] else "DELETE", f"{base}/{endpoint}")
            done.append(f"{key} -> {s[key]}")
    if "actions_permissions" in changed:
        gh("PUT", f"{base}/actions/permissions", s["actions_permissions"])
        done.append(f"actions_permissions -> {json.dumps(s['actions_permissions'])}")
    if "workflow_permissions" in changed:
        gh("PUT", f"{base}/actions/permissions/workflow", s["workflow_permissions"])
        done.append(f"workflow_permissions -> {json.dumps(s['workflow_permissions'])}")

    for rs in want["rulesets"]:
        if not dry["rulesets"].get(rs["name"]):
            continue
        live = dry["live_rulesets"].get(rs["name"])
        if live is None:
            _, created = gh("POST", f"{base}/rulesets", rs)
            done.append(f"ruleset {rs['name']} created (id {created['id']})")
        else:
            gh("PUT", f"{base}/rulesets/{live['id']}", rs)
            done.append(f"ruleset {rs['name']} updated (id {live['id']}): "
                        + "; ".join(dry["rulesets"][rs["name"]]))
    return done


# --------------------------------------------------------------------------- main


def select_repos(cfg: dict, names: list[str] | None) -> list[dict]:
    repos = cfg["repos"]["repos"]
    if not names:
        return repos
    wanted = {n.lower() for n in names}
    chosen = [r for r in repos if r["name"].lower() in wanted]
    missing = wanted - {r["name"].lower() for r in chosen}
    if missing:
        sys.exit(f"error: not in policies/repos.json: {', '.join(sorted(missing))}")
    return chosen


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("command", nargs="?", default="plan", choices=["validate", "plan", "apply", "audit"])
    parser.add_argument("--repo", action="append", help="limit to this repository (repeatable)")
    parser.add_argument("--scope", choices=["full", "public"], default="full",
                        help="plan/audit only: 'public' works with a read-only token (default: full)")
    args = parser.parse_args(argv)

    cfg = load_config()
    errors = validate(cfg)
    if errors:
        print("Policy files are invalid:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    if args.command == "validate":
        print(f"OK: {len(cfg['repos']['repos'])} repositories, policy files valid.")
        return 0

    owner = cfg["repos"]["owner"]
    repos = select_repos(cfg, args.repo)
    scope = "full" if args.command == "apply" else args.scope
    drifted, failed = 0, 0
    for repo in repos:
        try:
            result = plan_repo(cfg, owner, repo, scope)
        except ApiError as exc:
            failed += 1
            print(f"\n== {repo['name']}: ERROR {exc}")
            continue
        print_plan(result)
        if not has_drift(result):
            continue
        drifted += 1
        if args.command == "apply":
            try:
                for line in apply_repo(cfg, owner, repo, result):
                    print(f"  + applied {line}")
            except ApiError as exc:
                failed += 1
                print(f"  ! apply failed: {exc}")

    print(f"\nSummary ({args.command}, scope={scope}): {len(repos)} repositories, "
          f"{drifted} with drift, {failed} errors.")
    if args.command == "apply" and drifted:
        print("Run 'plan' again to confirm zero drift.")
    if failed:
        return 2
    if args.command == "audit" and drifted:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
