import io
import json
import os
import re
import shutil
import unittest
from contextlib import redirect_stdout

import trust_graph as tg
from tests import fixture_util

TWELVE = re.compile(r"\d{12}")


class FixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.list_roles, cls.get_role_dir = fixture_util.materialize()
        cls.roles = tg.load_roles(cls.list_roles, cls.get_role_dir)
        cls.analysis = tg.analyze(cls.roles)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def flags_for(self, role):
        return [f["issue"] for f in self.analysis["findings"] if f["role"] == role]

    def test_committed_fixtures_have_no_account_ids(self):
        for root, _dirs, files in os.walk(fixture_util.FIXTURES):
            for name in files:
                with open(os.path.join(root, name)) as fh:
                    self.assertIsNone(TWELVE.search(fh.read()), name)

    def test_materialized_fixture_has_account_ids(self):
        with open(self.list_roles) as fh:
            self.assertIsNotNone(TWELVE.search(fh.read()))

    def test_get_role_overrides_list_roles(self):
        lam = [r for r in self.roles if r["RoleName"] == "lambda-exec"][0]
        self.assertEqual(lam["Description"], "from get-role")

    def test_service_linked_roles_skipped_by_default(self):
        self.assertNotIn("AWSServiceRoleForSupport", self.analysis["roles"])
        self.assertIn("AWSServiceRoleForSupport", tg.analyze(self.roles, include_service_linked=True)["roles"])

    def test_cross_account_with_external_id_not_flagged(self):
        self.assertEqual(self.flags_for("partner-readonly"), [])

    def test_bare_account_without_external_id_flagged(self):
        self.assertEqual(self.flags_for("vendor-audit"), ["cross-account trust without sts:ExternalId"])

    def test_wildcard_principal_flagged_even_with_conditions(self):
        flags = self.flags_for("break-glass")
        self.assertEqual(len(flags), 1)
        self.assertIn("wildcard principal (conditions present", flags[0])

    def test_same_account_role_not_flagged(self):
        self.assertEqual(self.flags_for("same-account-admin"), [])

    def test_principal_list_produces_one_edge_each(self):
        edges = [e for e in self.analysis["edges"] if e["role"] == "shared-deploy"]
        self.assertEqual(sorted(e["principal"]["category"] for e in edges), ["aws-role", "aws-user"])
        self.assertEqual(len(self.flags_for("shared-deploy")), 2)

    def test_deny_statements_ignored(self):
        edges = [e for e in self.analysis["edges"] if e["role"] == "shared-deploy"]
        self.assertTrue(all(e["principal"]["category"] != "wildcard" for e in edges))

    def test_url_encoded_trust_document(self):
        edges = [e for e in self.analysis["edges"] if e["role"] == "ecs-task"]
        self.assertEqual(edges[0]["principal"]["value"], "ecs-tasks.amazonaws.com")

    def test_oidc_without_conditions_flagged(self):
        self.assertEqual(len(self.flags_for("oidc-any-repo")), 1)
        self.assertEqual(self.flags_for("github-deployer"), [])

    def test_saml_category(self):
        edges = [e for e in self.analysis["edges"] if e["role"] == "sso-admins"]
        self.assertEqual(edges[0]["principal"]["category"], "federated-saml")

    def test_mermaid_redacted_and_well_formed(self):
        text = tg.to_mermaid(self.analysis)
        self.assertIsNone(TWELVE.search(text))
        self.assertTrue(text.startswith("flowchart LR\n"))
        self.assertIn("#lt;account-id#gt;", text)
        self.assertIn("external account #1", text)
        self.assertIn("linkStyle", text)
        for line in text.splitlines():
            m = re.match(r"\s+(p\d+|r\d+)\[", line)
            if m:
                self.assertRegex(m.group(1), r"^[pr]\d+$")

    def test_findings_markdown_redacted(self):
        text = tg.findings_markdown(self.analysis)
        self.assertIsNone(TWELVE.search(text))
        self.assertIn("<account-id>", text)

    def test_main_writes_files_and_exit_codes(self):
        out = os.path.join(self.tmp, "out")
        os.makedirs(out)
        args = [self.list_roles, "--out", os.path.join(out, "g.mmd"), "--findings", os.path.join(out, "f.md")]
        with redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(tg.main(args), 0)
            self.assertEqual(tg.main(args + ["--fail-on-findings"]), 1)
        self.assertIsNone(TWELVE.search(buf.getvalue()))
        self.assertTrue(os.path.getsize(os.path.join(out, "g.mmd")) > 0)


class UnitTest(unittest.TestCase):
    def test_redact(self):
        acct = "9" * 12
        self.assertEqual(tg.redact("arn:aws:iam::%s:root" % acct), "arn:aws:iam::<account-id>:root")
        self.assertEqual(tg.redact("x" + "1" * 13), "x" + "1" * 13)  # 13 digits is not an account id

    def test_classify_wildcard_string_principal(self):
        statement = {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}
        self.assertEqual(list(tg.principals_of(statement)), [("AWS", "*")])

    def test_has_condition_key_case_insensitive(self):
        self.assertTrue(tg.has_condition_key({"StringEquals": {"STS:ExternalID": "x"}}, "sts:ExternalId"))
        self.assertFalse(tg.has_condition_key({}, "sts:ExternalId"))

    def test_not_principal_flagged(self):
        acct = "7" * 12
        role = {"RoleName": "np", "Arn": "arn:aws:iam::%s:role/np" % acct,
                "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "NotPrincipal": {"AWS": "arn:aws:iam::%s:root" % acct},
                                                            "Action": "sts:AssumeRole"}]}}
        analysis = tg.analyze([role])
        self.assertIn("NotPrincipal", analysis["findings"][0]["issue"])

    def test_parse_trust_document_variants(self):
        doc = {"Statement": []}
        self.assertEqual(tg.parse_trust_document(doc), doc)
        self.assertEqual(tg.parse_trust_document(json.dumps(doc)), doc)
        self.assertEqual(tg.parse_trust_document("%7B%22Statement%22%3A%20%5B%5D%7D"), doc)
        self.assertEqual(tg.parse_trust_document(None), doc)


if __name__ == "__main__":
    unittest.main()
