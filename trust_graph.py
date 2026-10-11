#!/usr/bin/env python3
"""Draw who can assume which IAM role, and flag risky trust policies.

Input: the JSON from `aws iam list-roles --output json`, optionally plus a
directory of `aws iam get-role --role-name X --output json` files.

Output: a Mermaid flowchart (principal --> role) and a Markdown findings list.
Every 12-digit account ID is redacted to <account-id>. External accounts get
stable aliases (external account #1, #2, ...) so the graph stays readable.

Flags:
  * wildcard principal ("*" or {"AWS": "*"}), even when conditions exist
  * cross-account AWS principal without an sts:ExternalId condition
  * Allow with NotPrincipal
  * OIDC web-identity trust without any condition
"""
import argparse
import glob
import json
import os
import re
import sys
from urllib.parse import unquote

ACCOUNT_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
BARE_ACCOUNT_RE = re.compile(r"^\d{12}$")
SERVICE_LINKED_PATH = "/aws-service-role/"


def redact(text):
    return ACCOUNT_RE.sub("<account-id>", str(text))


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_trust_document(doc):
    """list-roles returns the trust policy as an object (CLI) or URL-encoded JSON (raw API)."""
    if isinstance(doc, dict):
        return doc
    if not doc:
        return {"Statement": []}
    try:
        return json.loads(doc)
    except ValueError:
        return json.loads(unquote(doc))


def account_of_arn(arn):
    parts = str(arn).split(":")
    return parts[4] if len(parts) > 5 else ""


def load_roles(list_roles_path, get_role_dir=None):
    with open(list_roles_path) as fh:
        data = json.load(fh)
    roles = data.get("Roles", []) if isinstance(data, dict) else list(data)
    by_name = {r["RoleName"]: r for r in roles}
    if get_role_dir:
        for path in sorted(glob.glob(os.path.join(get_role_dir, "*.json"))):
            with open(path) as fh:
                obj = json.load(fh)
            role = obj.get("Role", obj)
            if "RoleName" in role:
                by_name[role["RoleName"]] = role
    return [by_name[name] for name in sorted(by_name)]


def classify_principal(kind, value, own_account):
    """Return a dict describing one principal entry from a trust policy."""
    info = {"kind": kind, "value": value, "account": "", "cross_account": False, "category": kind.lower()}
    if value == "*":
        info["category"] = "wildcard"
        return info
    if kind == "AWS":
        if BARE_ACCOUNT_RE.match(value):
            info["account"] = value
            info["category"] = "aws-account"
        else:
            info["account"] = account_of_arn(value)
            resource = value.split(":", 5)[-1] if value.count(":") >= 5 else value
            if resource == "root":
                info["category"] = "aws-account"
            elif resource.startswith("role/"):
                info["category"] = "aws-role"
            elif resource.startswith("user/"):
                info["category"] = "aws-user"
            else:
                info["category"] = "aws-other"
        info["cross_account"] = bool(info["account"]) and info["account"] != own_account
    elif kind == "Service":
        info["category"] = "service"
    elif kind == "Federated":
        if ":saml-provider/" in value:
            info["category"] = "federated-saml"
        elif ":oidc-provider/" in value:
            info["category"] = "federated-oidc"
        else:
            info["category"] = "federated-web"
    return info


def has_condition_key(condition, key):
    key = key.lower()
    for operator_block in (condition or {}).values():
        if isinstance(operator_block, dict) and any(k.lower() == key for k in operator_block):
            return True
    return False


def principals_of(statement):
    principal = statement.get("Principal")
    if principal == "*":
        yield "AWS", "*"
        return
    if isinstance(principal, dict):
        for kind in sorted(principal):
            for value in _as_list(principal[kind]):
                yield kind, value


def analyze(roles, include_service_linked=False):
    edges, findings, analyzed = [], [], []
    for role in roles:
        if not include_service_linked and role.get("Path", "/").startswith(SERVICE_LINKED_PATH):
            continue
        name, arn = role["RoleName"], role.get("Arn", "")
        own = account_of_arn(arn)
        analyzed.append(name)
        doc = parse_trust_document(role.get("AssumeRolePolicyDocument"))
        for statement in _as_list(doc.get("Statement")):
            if statement.get("Effect") != "Allow":
                continue
            actions = sorted(_as_list(statement.get("Action")))
            condition = statement.get("Condition") or {}
            if "NotPrincipal" in statement:
                findings.append({"role": name, "issue": "Allow with NotPrincipal (trusts everyone not listed)",
                                 "principal": json.dumps(statement["NotPrincipal"], sort_keys=True)})
            for kind, value in principals_of(statement):
                info = classify_principal(kind, value, own)
                flags = []
                if info["category"] == "wildcard":
                    flags.append("wildcard principal" + (" (conditions present: review them)" if condition else ""))
                if info["cross_account"] and not has_condition_key(condition, "sts:ExternalId"):
                    flags.append("cross-account trust without sts:ExternalId")
                if info["category"] == "federated-oidc" and not condition:
                    flags.append("OIDC trust without conditions (any repo/subject)")
                edge = {"role": name, "role_account": own, "principal": info, "actions": actions, "flags": flags}
                edges.append(edge)
                for flag in flags:
                    findings.append({"role": name, "issue": flag, "principal": value})
    return {"roles": analyzed, "edges": edges, "findings": findings}


def _account_aliases(edges):
    """Stable, non-identifying labels for every account seen."""
    aliases, external = {}, 0
    for edge in edges:
        aliases.setdefault(edge["role_account"], "this account")
    for edge in edges:
        acct = edge["principal"]["account"]
        if acct and acct not in aliases:
            external += 1
            aliases[acct] = "external account #%d" % external
    return aliases


def _mermaid_text(text):
    return (redact(text).replace("&", "#amp;").replace('"', "#quot;")
            .replace("<", "#lt;").replace(">", "#gt;"))


def principal_label(info, aliases):
    if info["category"] == "wildcard":
        return "ANYONE: *"
    label = "%s: %s" % (info["kind"], info["value"])
    if info["account"]:
        label += " [%s]" % aliases.get(info["account"], "external account")
    return label


def to_mermaid(analysis):
    edges = analysis["edges"]
    aliases = _account_aliases(edges)
    lines = ["flowchart LR",
             "  classDef role fill:#eef4ff,stroke:#3b6fd8,color:#111",
             "  classDef risky fill:#ffecec,stroke:#d33,color:#111",
             "  classDef principal fill:#f6f6f6,stroke:#888,color:#111",
             "  classDef wildcard fill:#ffd6d6,stroke:#b00,color:#111"]
    principal_ids, role_ids, risky_roles, flagged_links = {}, {}, set(), []
    for role in analysis["roles"]:
        role_ids[role] = "r%d" % (len(role_ids) + 1)
        lines.append('  %s["role: %s"]:::role' % (role_ids[role], _mermaid_text(role)))
    for edge in edges:
        info = edge["principal"]
        key = (info["kind"], info["value"])
        if key not in principal_ids:
            principal_ids[key] = "p%d" % (len(principal_ids) + 1)
            css = "wildcard" if info["category"] == "wildcard" else "principal"
            lines.append('  %s["%s"]:::%s' % (principal_ids[key], _mermaid_text(principal_label(info, aliases)), css))
    for index, edge in enumerate(edges):
        label = ", ".join(a.replace("sts:", "") for a in edge["actions"]) or "trust"
        if edge["flags"]:
            label = "FLAG: " + "; ".join(edge["flags"])
            risky_roles.add(edge["role"])
            flagged_links.append(index)
        lines.append('  %s -->|"%s"| %s' % (principal_ids[(edge["principal"]["kind"], edge["principal"]["value"])],
                                           _mermaid_text(label), role_ids[edge["role"]]))
    for role in sorted(risky_roles):
        lines.append("  class %s risky" % role_ids[role])
    if flagged_links:
        lines.append("  linkStyle %s stroke:#d33,stroke-width:2px" % ",".join(str(i) for i in flagged_links))
    return "\n".join(lines) + "\n"


def findings_markdown(analysis):
    lines = ["# Trust policy findings", "",
             "Roles analyzed: %d. Trust edges: %d. Findings: %d." % (
                 len(analysis["roles"]), len(analysis["edges"]), len(analysis["findings"])), ""]
    if not analysis["findings"]:
        lines.append("No wildcard principals, no cross-account trust without sts:ExternalId.")
    else:
        lines.append("| Role | Issue | Principal |")
        lines.append("|---|---|---|")
        for f in analysis["findings"]:
            lines.append("| %s | %s | `%s` |" % (redact(f["role"]), f["issue"], redact(f["principal"])))
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("list_roles_json", help="output of: aws iam list-roles --output json")
    parser.add_argument("--get-role-dir", help="directory of get-role JSON files (optional)")
    parser.add_argument("--out", default="trust-graph.mmd", help="Mermaid output path")
    parser.add_argument("--findings", default="findings.md", help="Markdown findings path")
    parser.add_argument("--include-service-linked", action="store_true",
                        help="include /aws-service-role/ roles (skipped by default)")
    parser.add_argument("--fail-on-findings", action="store_true", help="exit 1 when anything is flagged")
    args = parser.parse_args(argv)

    analysis = analyze(load_roles(args.list_roles_json, args.get_role_dir), args.include_service_linked)
    with open(args.out, "w") as fh:
        fh.write(to_mermaid(analysis))
    with open(args.findings, "w") as fh:
        fh.write(findings_markdown(analysis))
    print("roles=%d edges=%d findings=%d -> %s, %s" % (
        len(analysis["roles"]), len(analysis["edges"]), len(analysis["findings"]), args.out, args.findings))
    for f in analysis["findings"]:
        print("  FLAG %s: %s (%s)" % (redact(f["role"]), f["issue"], redact(f["principal"])))
    return 1 if (args.fail_on_findings and analysis["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
