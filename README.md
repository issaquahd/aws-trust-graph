# aws-trust-graph

See who can assume which IAM role in an account, as a Mermaid graph, with risky trust policies flagged and every account ID redacted.

## What it does

`trust_graph.py` reads the JSON from `aws iam list-roles --output json`, and optionally a folder of `aws iam get-role` outputs. It parses each role's trust policy, whether returned as an object or URL-encoded, and draws **principal --> role** edges for:

* service principals (`lambda.amazonaws.com`, ...)
* AWS principals: account root, bare account ID, role, user. Own account vs. external accounts is decided from the role ARN *before* redaction.
* federated principals: SAML providers, OIDC providers, web identity

It flags:

* **wildcard principals** (`"*"` / `{"AWS": "*"}`), even when conditions exist, so a human reviews them
* **cross-account trust without an `sts:ExternalId` condition**
* `Allow` with `NotPrincipal`
* OIDC trust with no conditions at all (any repo or subject could assume it)

Every 12-digit number becomes `<account-id>` (written as `#lt;account-id#gt;` inside Mermaid labels so it renders). External accounts get stable aliases (`external account #1`, `#2`, ...) so the graph stays readable without revealing IDs. Service-linked roles (`/aws-service-role/`) are skipped unless you pass `--include-service-linked`.

Example output from the synthetic fixtures: [`examples/trust-graph.mmd`](examples/trust-graph.mmd), [`examples/findings.md`](examples/findings.md). Architecture: [`diagram.mmd`](diagram.mmd).

## Run it

In AWS CloudShell (read-only, creates nothing):

```bash
./collect.sh                    # list-roles -> out/trust-graph.mmd + out/findings.md
WITH_GET_ROLE=1 ./collect.sh    # also get-role per role
rm -rf out                      # the raw JSON in out/ holds real account IDs
```

Locally, against any saved list-roles JSON:

```bash
python3 trust_graph.py list-roles.json --out trust-graph.mmd --findings findings.md [--fail-on-findings]
```

Tests (offline, standard library only): `python3 -m unittest discover -s tests -t .`

The committed fixtures use `ACCOUNT_*` placeholders. The tests swap in synthetic 12-digit IDs at runtime, so redaction is tested for real and no account-shaped number is ever committed. Regenerate the examples with `python3 -m tests.fixture_util examples`.

## Deploy / verify / teardown

Nothing is deployed. `collect.sh` makes only read-only IAM calls. Teardown is `rm -rf out`.

## The learning

A role's permissions policy says what it can do, and its trust policy says who can become it. That second question is the one that gets missed. Drawing every trust edge in one picture makes wildcard principals and cross-account trust without an ExternalId stand out immediately. Redact before you share, because account IDs are not secrets, but they are reconnaissance.

---

Independent project by Alex Alvord, CloudLab Works. MIT licensed.
