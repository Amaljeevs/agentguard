import unittest

from import_gpg_key import import_error, normalize_key


class KeyFormattingTest(unittest.TestCase):
    armor = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nYWJj\n-----END PGP PRIVATE KEY BLOCK-----\n"

    def test_valid_export_is_preserved(self):
        self.assertEqual(normalize_key(self.armor), self.armor)

    def test_escaped_newlines(self):
        self.assertEqual(normalize_key(self.armor.replace("\n", r"\n")), self.armor)

    def test_missing_separator(self):
        self.assertEqual(normalize_key(self.armor.replace("\n\n", "\n")), self.armor)

    def test_separator_after_optional_armor_headers(self):
        expected = self.armor.replace("\n\n", "\nVersion: exporter\nComment: test\n\n")
        self.assertEqual(normalize_key(expected.replace("test\n\n", "test\n")), expected)

    def test_crlf(self):
        for newline in ("\r\n", r"\r\n"):
            self.assertEqual(normalize_key(self.armor.replace("\n", newline)), self.armor)

    def test_diagnostics_do_not_echo_input(self):
        for error in (b"invalid armor header: PRIVATE_DATA", b"CRC error PRIVATE_DATA",
                      b"no valid OpenPGP data PRIVATE_DATA", b"agent PRIVATE_DATA", b"PRIVATE_DATA"):
            self.assertNotIn("PRIVATE_DATA", import_error(error))


if __name__ == "__main__":
    unittest.main()
