# Trust policy findings

Roles analyzed: 10. Trust edges: 11. Findings: 5.

| Role | Issue | Principal |
|---|---|---|
| break-glass | wildcard principal (conditions present: review them) | `*` |
| oidc-any-repo | OIDC trust without conditions (any repo/subject) | `arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com` |
| shared-deploy | cross-account trust without sts:ExternalId | `arn:aws:iam::<account-id>:role/deploy` |
| shared-deploy | cross-account trust without sts:ExternalId | `arn:aws:iam::<account-id>:user/ci-bot` |
| vendor-audit | cross-account trust without sts:ExternalId | `<account-id>` |
