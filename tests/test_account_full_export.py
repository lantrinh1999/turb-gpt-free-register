# -*- coding: utf-8 -*-
import json
import unittest
from unittest import mock

import core.db as db


class AccountFullExportTests(unittest.TestCase):
    def _row(self, **overrides) -> dict:
        row = {
            "email": "a@b.com",
            "email_source": "gptmail",
            "extra_json": json.dumps({"registration_password": "Pass123"}),
            "totp_secret": "ABCDEF123",
        }
        row.update(overrides)
        return row

    def test_basic_format(self):
        line = db._account_full_export_line(self._row())
        self.assertEqual(
            line,
            "a@b.com---gptmail---Pass123---https://2fa.run/----2FA:ABCDEF123",
        )

    def test_separators_match_spec(self):
        # The first four segments are “---”, and before the 2FA segment is “----”
        line = db._account_full_export_line(self._row())
        self.assertTrue(line.startswith("a@b.com---gptmail---Pass123---https://2fa.run/----2FA:ABCDEF123"))
        self.assertIn("---https://2fa.run/----2FA:", line)

    def test_missing_registration_password_keeps_empty_field(self):
        row = self._row(extra_json=json.dumps({}))
        line = db._account_full_export_line(row)
        # An empty password is a “real empty field”, collapsed from adjacent “---” into “------”, keeping the 5-segment structure readable
        self.assertEqual(
            line,
            "a@b.com---gptmail------https://2fa.run/----2FA:ABCDEF123",
        )

    def test_missing_totp_keeps_prefix(self):
        row = self._row(totp_secret="")
        line = db._account_full_export_line(row)
        self.assertEqual(
            line,
            "a@b.com---gptmail---Pass123---https://2fa.run/----2FA:",
        )

    def test_password_from_top_level_registration_password(self):
        # Compatible with registration_password written directly at the top level (no extra_json)
        row = self._row(extra_json=None, registration_password="TopPw")
        line = db._account_full_export_line(row)
        self.assertIn("---TopPw---", line)

    def test_email_source_fallback_empty(self):
        row = self._row(email_source="")
        line = db._account_full_export_line(row)
        # Keep the empty field (------) when the source is empty, without breaking the overall structure
        self.assertTrue(line.startswith("a@b.com------Pass123---https://2fa.run/----2FA:ABCDEF123"))

    def test_generic_api_resolves_to_code_url_link(self):
        # generic_api accounts should resolve to the full code-retrieval link from the email pool, not the bare string generic_api
        with mock.patch.object(
            db, "get_generic_api_email_by_email",
            return_value={"code_url": "http://127.0.0.1:5055/code?email=a@b.com"},
        ):
            row = self._row(email_source="generic_api")
            line = db._account_full_export_line(row)
        self.assertEqual(
            line,
            "a@b.com---http://127.0.0.1:5055/code?email=a@b.com---Pass123---https://2fa.run/----2FA:ABCDEF123",
        )

    def test_generic_api_constructs_link_when_pool_missing(self):
        # When the email is not found in the email pool, build the full code-retrieval link following the OmniMail convention
        import config.email as ce
        with mock.patch.object(
            db, "get_generic_api_email_by_email", return_value=None
        ), mock.patch.object(ce, "OMNIMAIL_BASE", "https://omnimail.example/api", create=True):
            row = self._row(email_source="generic_api")
            line = db._account_full_export_line(row)
        self.assertEqual(
            line,
            "a@b.com---https://omnimail.example/api/messages?mailbox=a@b.com---Pass123---https://2fa.run/----2FA:ABCDEF123",
        )

    def test_build_code_url_with_base(self):
        import config.email as ce
        with mock.patch.object(ce, "OMNIMAIL_BASE", "https://example.com/api/", create=True):
            self.assertEqual(
                db._build_generic_api_code_url("a@b.com"),
                "https://example.com/api/messages?mailbox=a@b.com",
            )


if __name__ == "__main__":
    unittest.main()
