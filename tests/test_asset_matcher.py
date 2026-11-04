import unittest

from core.asset_matcher import normalize_name, match_assets_to_kev, compare_versions, evaluate_version_range, parse_cpe23, _combine_results, _evaluate_cpe_match, _evaluate_cpe_match_for_host


class TestAssetMatcher(unittest.TestCase):

    def test_normalizes_case_and_punctuation(self):
        self.assertEqual(
            normalize_name("  ACME-Corp, Inc. "),
            "acme corp inc"
        )

    def test_normalizes_unicode(self):
        self.assertEqual(normalize_name("ＡＣＭＥ"), "acme")

    def test_rejects_non_string_values(self):
        self.assertEqual(normalize_name(None), "")

    def test_matches_vendor_and_product(self):
        assets = [
            {"vendor": "Example Corp.", "product": "Widget Pro", "version": "2.1"}
        ]
        vulnerabilities = [
            {
                "cve_id": "CVE-2025-1234",
                "vendor": "Example Corp",
                "product": "Widget Pro",
                "source": "CISA KEV",
                "source_url": "https://example.com/advisory",
            }
        ]

        results = match_assets_to_kev(assets, vulnerabilities)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve_id"], "CVE-2025-1234")
        self.assertEqual(results[0]["match_status"], "potential_match")
        self.assertEqual(results[0]["source"], "CISA KEV")

    def test_does_not_match_different_vendor(self):
        assets = [{"vendor": "Other Corp", "product": "Widget Pro"}]
        vulnerabilities = [{"vendor": "Example Corp", "product": "Widget Pro"}]

        self.assertEqual(match_assets_to_kev(assets, vulnerabilities), [])

    def test_does_not_match_different_product(self):
        assets = [{"vendor": "Example Corp", "product": "Widget Basic"}]
        vulnerabilities = [{"vendor": "Example Corp", "product": "Widget Pro"}]

        self.assertEqual(match_assets_to_kev(assets, vulnerabilities), [])

    def test_skips_incomplete_assets(self):
        assets = [
            {"vendor": "Example Corp", "product": ""},
            {"vendor": None, "product": "Widget Pro"},
        ]
        vulnerabilities = [
            {"vendor": "Example Corp", "product": "Widget Pro"}
        ]

        self.assertEqual(match_assets_to_kev(assets, vulnerabilities), [])

    def test_skips_malformed_records(self):
        assets = [
            None,
            "invalid",
            {"vendor": "Example Corp", "product": "Widget Pro"},
        ]
        vulnerabilities = [
            None,
            "invalid",
            {"vendor": "Example Corp", "product": "Widget Pro"},
        ]

        results = match_assets_to_kev(assets, vulnerabilities)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["match_status"], "potential_match")

    def test_rejects_invalid_collections(self):
        self.assertEqual(match_assets_to_kev(None, []), [])
        self.assertEqual(match_assets_to_kev([], None), [])
        self.assertEqual(match_assets_to_kev("invalid", []), [])
        self.assertEqual(match_assets_to_kev([], "invalid"), [])



class TestVersionComparison(unittest.TestCase):

    def test_lower_version(self):
        self.assertEqual(compare_versions("2.0", "3.0"), -1)

    def test_equal_versions(self):
        self.assertEqual(compare_versions("2.5", "2.5"), 0)

    def test_higher_version(self):
        self.assertEqual(compare_versions("10.2", "2.9"), 1)

    def test_equivalent_trailing_zero(self):
        self.assertEqual(compare_versions("2.5", "2.5.0"), 0)

    def test_unsupported_version_format(self):
        self.assertIsNone(compare_versions("2.5-beta", "2.5"))

    def test_rejects_non_string_versions(self):
        self.assertIsNone(compare_versions(None, "2.5"))


class TestVersionRangeEvaluation(unittest.TestCase):

    def test_inclusive_start_and_exclusive_end(self):
        cpe = {
            "version_start_including": "2.0",
            "version_end_excluding": "3.0",
        }

        self.assertEqual(
            evaluate_version_range("2.0", cpe), "range_match"
        )
        self.assertEqual(
            evaluate_version_range("2.5", cpe), "range_match"
        )
        self.assertEqual(
            evaluate_version_range("3.0", cpe), "no_match"
        )

    def test_exclusive_start_and_inclusive_end(self):
        cpe = {
            "version_start_excluding": "2.0",
            "version_end_including": "3.0",
        }

        self.assertEqual(
            evaluate_version_range("2.0", cpe), "no_match"
        )
        self.assertEqual(
            evaluate_version_range("3.0", cpe), "range_match"
        )

    def test_version_below_range(self):
        cpe = {"version_start_including": "2.0"}
        self.assertEqual(
            evaluate_version_range("1.9", cpe), "no_match"
        )

    def test_version_above_range(self):
        cpe = {"version_end_including": "3.0"}
        self.assertEqual(
            evaluate_version_range("3.1", cpe), "no_match"
        )

    def test_missing_boundaries_are_indeterminate(self):
        self.assertEqual(
            evaluate_version_range("2.5", {}), "indeterminate"
        )

    def test_unsupported_version_is_indeterminate(self):
        cpe = {"version_start_including": "2.0"}
        self.assertEqual(
            evaluate_version_range("2.5-beta", cpe), "indeterminate"
        )

    def test_invalid_cpe_input_is_indeterminate(self):
        self.assertEqual(
            evaluate_version_range("2.5", None), "indeterminate"
        )


    def test_rejects_conflicting_start_boundaries(self):
        cpe = {
            "version_start_including": "2.0",
            "version_start_excluding": "2.1",
        }
        self.assertEqual(
            evaluate_version_range("2.5", cpe),
            "indeterminate",
        )

    def test_rejects_conflicting_end_boundaries(self):
        cpe = {
            "version_end_including": "3.0",
            "version_end_excluding": "3.1",
        }
        self.assertEqual(
            evaluate_version_range("2.5", cpe),
            "indeterminate",
        )

    def test_rejects_reversed_version_range(self):
        cpe = {
            "version_start_including": "4.0",
            "version_end_including": "3.0",
        }
        self.assertEqual(
            evaluate_version_range("3.5", cpe),
            "indeterminate",
        )
class TestCPEParser(unittest.TestCase):
    def test_parses_valid_cpe(self):
        result = parse_cpe23(
            "cpe:2.3:a:example:widget:2.1:*:*:*:*:*:*:*"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["vendor"], "example")
        self.assertEqual(result["product"], "widget")
        self.assertEqual(result["version"], "2.1")

    def test_handles_escaped_colon(self):
        result = parse_cpe23(
            r"cpe:2.3:a:example\:corp:widget:2.1:*:*:*:*:*:*:*"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["vendor"], "example:corp")

    def test_preserves_wildcard_identity(self):
        result = parse_cpe23(
            r"cpe:2.3:a:example:literal\*:2.1:*:*:*:*:*:*:*"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["product"], "literal*")
        self.assertFalse(result["product_is_wildcard"])

    def test_rejects_invalid_escape_sequence(self):
        criteria = r"cpe:2.3:a:example:wid\aet:2.1:*:*:*:*:*:*:*"
        self.assertIsNone(parse_cpe23(criteria))

    def test_accepts_escaped_question_mark(self):
        criteria = r"cpe:2.3:a:example:wid\?et:2.1:*:*:*:*:*:*:*"
        result = parse_cpe23(criteria)
        self.assertIsNotNone(result)
        self.assertEqual(result["product"], "wid?et")
        self.assertFalse(result["product_is_wildcard"])

    def test_rejects_dangling_backslash(self):
        criteria = "cpe:2.3:a:example:widget:2.1:*:*:*:*:*:*:\\"
        self.assertIsNone(parse_cpe23(criteria))

    def test_rejects_malformed_input(self):
        self.assertIsNone(parse_cpe23("not-a-cpe"))
        self.assertIsNone(parse_cpe23("cpe:2.3:a:example:widget"))

    def test_accepts_valid_part_values(self):
        for part in ("a", "o", "h", "*", "-"):
            with self.subTest(part=part):
                criteria = f"cpe:2.3:{part}:example:widget:2.1:*:*:*:*:*:*:*"
                self.assertIsNotNone(parse_cpe23(criteria))

    def test_parses_all_cpe23_attributes_in_standard_order(self):
        criteria = (
            "cpe:2.3:a:microsoft:windows_10:22h2:"
            "*:*:*:*:windows_11:x64:*"
        )

        result = parse_cpe23(criteria)

        self.assertIsNotNone(result)
        self.assertEqual(result["version"], "22h2")
        self.assertEqual(result["target_sw"], "windows_11")
        self.assertEqual(result["target_hw"], "x64")
        self.assertFalse(result["target_sw_is_wildcard"])
        self.assertFalse(result["target_hw_is_wildcard"])
        self.assertTrue(result["update_is_wildcard"])
        self.assertTrue(result["other_is_wildcard"])

    def test_rejects_invalid_part_value(self):
        criteria = "cpe:2.3:x:example:widget:2.1:*:*:*:*:*:*:*"
        self.assertIsNone(parse_cpe23(criteria))
if __name__ == "__main__":
    unittest.main()



class TestBooleanLogic(unittest.TestCase):
    def test_and_all_match(self):
        self.assertEqual(
            _combine_results("AND", ["match", "match"]),
            "match",
        )

    def test_and_one_no_match(self):
        self.assertEqual(
            _combine_results("AND", ["match", "no_match"]),
            "no_match",
        )

    def test_and_indeterminate(self):
        self.assertEqual(
            _combine_results("AND", ["match", "indeterminate"]),
            "indeterminate",
        )

    def test_or_one_match(self):
        self.assertEqual(
            _combine_results("OR", ["no_match", "match"]),
            "match",
        )

    def test_or_all_no_match(self):
        self.assertEqual(
            _combine_results("OR", ["no_match", "no_match"]),
            "no_match",
        )

    def test_or_indeterminate(self):
        self.assertEqual(
            _combine_results("OR", ["no_match", "indeterminate"]),
            "indeterminate",
        )

    def test_nested_results_can_be_combined(self):
        inner = _combine_results("AND", ["match", "indeterminate"])
        outer = _combine_results("OR", [inner, "match"])

        self.assertEqual(inner, "indeterminate")
        self.assertEqual(outer, "match")

    def test_rejects_invalid_operator(self):
        self.assertEqual(
            _combine_results("XOR", ["match", "match"]),
            "indeterminate",
        )

    def test_rejects_empty_results(self):
        self.assertEqual(_combine_results("AND", []), "indeterminate")

    def test_rejects_invalid_result(self):
        self.assertEqual(
            _combine_results("AND", ["match", "unknown"]),
            "indeterminate",
        )



class TestCPEMatchEvaluation(unittest.TestCase):
    def test_matches_exact_asset_identity_and_version(self):
        asset = {
            "part": "a",
            "vendor": "example",
            "product": "widget",
            "version": "2.1",
        }
        cpe = {
            "criteria": "cpe:2.3:a:example:widget:2.1:*:*:*:*:*:*:*",
            "vulnerable": True,
        }

        self.assertEqual(_evaluate_cpe_match(asset, cpe), "match")

    def test_rejects_different_vendor(self):
        asset = {
            "part": "a",
            "vendor": "other",
            "product": "widget",
            "version": "2.1",
        }
        cpe = {
            "criteria": "cpe:2.3:a:example:widget:2.1:*:*:*:*:*:*:*",
            "vulnerable": True,
        }

        self.assertEqual(_evaluate_cpe_match(asset, cpe), "no_match")

    def test_rejects_different_product(self):
        asset = {
            "part": "a",
            "vendor": "example",
            "product": "different",
            "version": "2.1",
        }
        cpe = {
            "criteria": "cpe:2.3:a:example:widget:2.1:*:*:*:*:*:*:*",
            "vulnerable": True,
        }

        self.assertEqual(_evaluate_cpe_match(asset, cpe), "no_match")

    def test_rejects_different_version(self):
        asset = {
            "part": "a",
            "vendor": "example",
            "product": "widget",
            "version": "3.0",
        }
        cpe = {
            "criteria": "cpe:2.3:a:example:widget:2.1:*:*:*:*:*:*:*",
            "vulnerable": True,
        }

        self.assertEqual(_evaluate_cpe_match(asset, cpe), "no_match")

    def test_missing_asset_version_is_indeterminate(self):
        asset = {
            "part": "a",
            "vendor": "example",
            "product": "widget",
        }
        cpe = {
            "criteria": "cpe:2.3:a:example:widget:2.1:*:*:*:*:*:*:*",
            "vulnerable": True,
        }

        self.assertEqual(
            _evaluate_cpe_match(asset, cpe),
            "indeterminate",
        )

    def test_matches_version_range(self):
        asset = {
            "part": "a",
            "vendor": "example",
            "product": "widget",
            "version": "2.5",
        }
        cpe = {
            "criteria": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*",
            "version_start_including": "2.0",
            "version_end_excluding": "3.0",
            "vulnerable": True,
        }

        self.assertEqual(_evaluate_cpe_match(asset, cpe), "match")

    def test_rejects_version_outside_range(self):
        asset = {
            "part": "a",
            "vendor": "example",
            "product": "widget",
            "version": "3.0",
        }
        cpe = {
            "criteria": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*",
            "version_start_including": "2.0",
            "version_end_excluding": "3.0",
            "vulnerable": True,
        }

        self.assertEqual(_evaluate_cpe_match(asset, cpe), "no_match")

    def test_malformed_criterion_is_indeterminate(self):
        asset = {
            "part": "a",
            "vendor": "example",
            "product": "widget",
            "version": "2.1",
        }

        self.assertEqual(
            _evaluate_cpe_match(asset, {"criteria": "invalid"}),
            "indeterminate",
        )


    def test_matches_environmental_cpe_without_calling_it_vulnerable(self):
        asset = {
            "part": "h",
            "vendor": "example",
            "product": "server",
            "version": "2.1",
        }
        cpe = {
            "criteria": "cpe:2.3:h:example:server:2.1:*:*:*:*:*:*:*",
            "vulnerable": False,
        }

        self.assertEqual(_evaluate_cpe_match(asset, cpe), "match")
        self.assertFalse(cpe["vulnerable"])


class TestHostLevelCPEEvaluation(unittest.TestCase):
    def setUp(self):
        self.cpe = {
            "criteria": "cpe:2.3:a:example:widget:2.1:*:*:*:*:*:*:*",
            "vulnerable": True,
        }

    def test_finds_match_across_host_assets(self):
        assets = [
            {"part": "o", "vendor": "example", "product": "linux", "version": "11"},
            {"part": "a", "vendor": "example", "product": "widget", "version": "2.1"},
        ]
        self.assertEqual(
            _evaluate_cpe_match_for_host(assets, self.cpe),
            "match",
        )

    def test_incomplete_inventory_returns_indeterminate(self):
        assets = [
            {"part": "a", "vendor": "other", "product": "widget", "version": "2.1"},
        ]
        self.assertEqual(
            _evaluate_cpe_match_for_host(assets, self.cpe),
            "indeterminate",
        )

    def test_complete_inventory_returns_no_match(self):
        assets = [
            {"part": "a", "vendor": "other", "product": "widget", "version": "2.1"},
        ]
        self.assertEqual(
            _evaluate_cpe_match_for_host(
                assets, self.cpe, inventory_complete=True
            ),
            "no_match",
        )

    def test_malformed_inventory_record_returns_indeterminate(self):
        assets = [
            {"part": "a", "vendor": "example", "product": "widget", "version": "2.1"},
            "malformed record",
        ]
        self.assertEqual(
            _evaluate_cpe_match_for_host(assets, self.cpe),
            "indeterminate",
        )
