import unittest

from vanity_rules import compile_rules, expand_pattern, matches


class RuleTests(unittest.TestCase):
    def test_native_syntax_is_expanded_without_changing_equality(self):
        self.assertEqual(expand_pattern("(xy){4}"), "XYXYXYXY")
        self.assertEqual(expand_pattern("xxxxa{4}"), "XXXXAAAA")
        self.assertEqual(expand_pattern("(ab)c{2}"), "ABCC")

    def test_presets_and_or_deduplication(self):
        self.assertEqual(compile_rules(["suffix:deadbeef", "repeat:8", "pair:4",
                                       "palindrome:5"], ["deadbeef|a{4}"]),
                         ["DEADBEEF", "XXXXXXXX", "XYXYXYXY", "GHIHG", "AAAA"])
        sequences = compile_rules(["sequence:6"], [])
        self.assertEqual(len(sequences), 22)
        self.assertIn("012345", sequences)
        self.assertIn("FEDCBA", sequences)
        self.assertNotIn("DEF012", sequences)
        self.assertEqual(len(compile_rules(["palindrome:40"], [])[0]), 40)

    def test_rejects_unsafe_or_malformed_patterns(self):
        for pattern in ("", "{2}", "X{0}", "X{9999999999}", "X{41}", "X{-1}",
                        "(XY", "XY)", "((XY)){2}", "()", "X{}", "X{2}{3}",
                        "X" * 41, "中文", "A.*", "A;B", "A B", "X{２}"):
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                expand_pattern(pattern)
        for rules, patterns in (([], []), ([], ["AB|"]), (["suffix:XYZ"], []),
                                (["repeat:1"], []), (["pair:21"], []),
                                (["sequence:17"], []), (["unknown:8"], []),
                                ([], ["A"] * 257)):
            with self.subTest(rules=rules, patterns=patterns), self.assertRaises(ValueError):
                compile_rules(rules, patterns)

    def test_fingerprint_matching(self):
        def fpr(suffix):
            return "0" * (40 - len(suffix)) + suffix
        self.assertTrue(matches(fpr("deadbeef"), "DEADBEEF"))
        self.assertTrue(matches(fpr("12121212"), "XYXYXYXY"))
        self.assertTrue(matches(fpr("11111111"), "XYXYXYXY"))
        self.assertFalse(matches(fpr("12121213"), "XYXYXYXY"))
        self.assertTrue(matches(fpr("12321"), "GHIHG"))
        self.assertFalse(matches(fpr("12341"), "GHIHG"))
        self.assertFalse(matches("ABC", "ABC"))


if __name__ == "__main__":
    unittest.main()
