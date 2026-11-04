import re
import unicodedata


def normalize_name(value):
    """Normalize a vendor or product name for conservative comparison."""
    if not isinstance(value, str):
        return ""

    value = unicodedata.normalize("NFKC", value).casefold()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())


def match_assets_to_kev(assets, vulnerabilities):
    """
    Find potential vendor/product matches between customer assets and CISA KEV.

    A name match is not proof that an installed version is vulnerable.
    """
    results = []

    if not isinstance(assets, (list, tuple)):
        return results

    if not isinstance(vulnerabilities, (list, tuple)):
        return results

    for asset in assets:
        if not isinstance(asset, dict):
            continue

        asset_vendor = normalize_name(asset.get("vendor"))
        asset_product = normalize_name(asset.get("product"))

        if not asset_vendor or not asset_product:
            continue

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue

            kev_vendor = normalize_name(vulnerability.get("vendor"))
            kev_product = normalize_name(vulnerability.get("product"))

            if not kev_vendor or not kev_product:
                continue

            if asset_vendor == kev_vendor and asset_product == kev_product:
                results.append({
                    "asset": asset,
                    "cve_id": vulnerability.get("cve_id"),
                    "kev_vendor": vulnerability.get("vendor"),
                    "kev_product": vulnerability.get("product"),
                    "match_status": "potential_match",
                    "match_reason": (
                        "Normalized vendor and product names match. "
                        "Installed-version impact has not been established."
                    ),
                    "source": vulnerability.get("source"),
                    "source_url": vulnerability.get("source_url"),
                })

    return results


def compare_versions(left, right):
    """Compare numeric dotted versions; return None when unsupported."""
    if not isinstance(left, str) or not isinstance(right, str):
        return None

    pattern = r"^[0-9]+(?:\.[0-9]+)*$"
    if not re.fullmatch(pattern, left) or not re.fullmatch(pattern, right):
        return None

    left_parts = tuple(int(part) for part in left.split("."))
    right_parts = tuple(int(part) for part in right.split("."))

    width = max(len(left_parts), len(right_parts))
    left_parts += (0,) * (width - len(left_parts))
    right_parts += (0,) * (width - len(right_parts))

    return (left_parts > right_parts) - (left_parts < right_parts)


def evaluate_version_range(installed_version, cpe_match):
    """Evaluate an installed version against NVD CPE version boundaries."""
    if not isinstance(cpe_match, dict):
        return "indeterminate"

    start_including = cpe_match.get("version_start_including")
    start_excluding = cpe_match.get("version_start_excluding")
    end_including = cpe_match.get("version_end_including")
    end_excluding = cpe_match.get("version_end_excluding")

    # Reject conflicting boundary definitions.
    if start_including is not None and start_excluding is not None:
        return "indeterminate"

    if end_including is not None and end_excluding is not None:
        return "indeterminate"

    boundaries = (
        start_including,
        start_excluding,
        end_including,
        end_excluding,
    )

    if not any(boundary is not None for boundary in boundaries):
        return "indeterminate"

    if not isinstance(installed_version, str):
        return "indeterminate"

    # Every supplied boundary must be a supported version.
    for boundary in boundaries:
        if boundary is not None:
            if compare_versions(installed_version, boundary) is None:
                return "indeterminate"

    # Reject ranges whose lower boundary exceeds their upper boundary.
    lower = start_including or start_excluding
    upper = end_including or end_excluding

    if lower is not None and upper is not None:
        comparison = compare_versions(lower, upper)

        if comparison is None or comparison > 0:
            return "indeterminate"

        if comparison == 0 and (
            start_excluding is not None or end_excluding is not None
        ):
            return "indeterminate"

    if start_including is not None:
        if compare_versions(installed_version, start_including) < 0:
            return "no_match"

    if start_excluding is not None:
        if compare_versions(installed_version, start_excluding) <= 0:
            return "no_match"

    if end_including is not None:
        if compare_versions(installed_version, end_including) > 0:
            return "no_match"

    if end_excluding is not None:
        if compare_versions(installed_version, end_excluding) >= 0:
            return "no_match"

    return "range_match"


def parse_cpe23(criteria):
    """Parse CPE 2.3 identity fields while preserving wildcard identity."""
    if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
        return None

    raw_fields = []
    current = []
    escaped = False

    for char in criteria:
        if escaped:
            current.append("\\")
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            raw_fields.append("".join(current))
            current = []
        else:
            current.append(char)

    if escaped:
        return None

    raw_fields.append("".join(current))

    if len(raw_fields) != 13:
        return None

    if raw_fields[0] != "cpe" or raw_fields[1] != "2.3":
        return None

    def decode_field(value):
        decoded = []
        escaped_char = False

        quoted_chars = {
            "\\", "?", "*", "!", '"', "#", "$", "%", "&",
            "'", "(", ")", "+", ",", "/", ":", ";", "<", "=",
            ">", "@", "[", "]", "^", "`", "{", "|", "}", "~",
        }

        for char in value:
            if escaped_char:
                if char not in quoted_chars:
                    return None
                decoded.append(char)
                escaped_char = False
            elif char == "\\":
                escaped_char = True
            else:
                decoded.append(char)

        if escaped_char:
            return None

        return "".join(decoded)

    fields = [decode_field(value) for value in raw_fields]

    if any(value is None for value in fields):
        return None

    attribute_names = (
        "part",
        "vendor",
        "product",
        "version",
        "update",
        "edition",
        "language",
        "sw_edition",
        "target_sw",
        "target_hw",
        "other",
    )

    parsed = {}

    for index, name in enumerate(attribute_names, start=2):
        parsed[name] = fields[index]
        parsed[f"{name}_is_wildcard"] = raw_fields[index] == "*"

    if parsed["part"] not in {"a", "o", "h", "*", "-"}:
        return None

    return parsed


def _combine_results(operator, results):
    """Combine tri-state evaluation results using AND or OR logic."""
    if not isinstance(operator, str):
        return "indeterminate"

    if not isinstance(results, (list, tuple)) or not results:
        return "indeterminate"

    if any(
        result not in {"match", "no_match", "indeterminate"}
        for result in results
    ):
        return "indeterminate"

    operator = operator.upper()

    if operator == "AND":
        if "no_match" in results:
            return "no_match"
        if all(result == "match" for result in results):
            return "match"
        return "indeterminate"

    if operator == "OR":
        if "match" in results:
            return "match"
        if all(result == "no_match" for result in results):
            return "no_match"
        return "indeterminate"

    return "indeterminate"


def _evaluate_cpe_match(asset, cpe_match):
    """Evaluate one NVD CPE criterion against one asset."""
    if not isinstance(asset, dict) or not isinstance(cpe_match, dict):
        return "indeterminate"

    if not isinstance(cpe_match.get("vulnerable"), bool):
        return "indeterminate"

    parsed = parse_cpe23(cpe_match.get("criteria"))

    if parsed is None:
        return "indeterminate"

    # Compare the CPE part: application, operating system, or hardware.
    if not parsed["part_is_wildcard"]:
        asset_part = asset.get("part")

        if not isinstance(asset_part, str) or not asset_part:
            return "indeterminate"

        if normalize_name(asset_part) != normalize_name(parsed["part"]):
            return "no_match"

    # Vendor and product must be identifiable.
    for attribute in ("vendor", "product"):
        expected = parsed[attribute]

        if parsed[f"{attribute}_is_wildcard"]:
            return "indeterminate"

        actual = asset.get(attribute)

        if not isinstance(actual, str) or not actual:
            return "indeterminate"

        if normalize_name(actual) != normalize_name(expected):
            return "no_match"

    # Evaluate version identity or NVD version boundaries.
    installed_version = asset.get("version")
    expected_version = parsed["version"]

    boundaries = (
        "version_start_including",
        "version_start_excluding",
        "version_end_including",
        "version_end_excluding",
    )

    has_boundaries = any(
        cpe_match.get(boundary) is not None
        for boundary in boundaries
    )

    if parsed["version_is_wildcard"]:
        if has_boundaries:
            result = evaluate_version_range(installed_version, cpe_match)

            if result == "range_match":
                pass
            elif result == "no_match":
                return "no_match"
            else:
                return "indeterminate"

        # A wildcard version without boundaries accepts any version.
        # A missing version does not prevent an identity-only match.
    else:
        if has_boundaries:
            return "indeterminate"

        if not isinstance(installed_version, str) or not installed_version:
            return "indeterminate"

        numeric_comparison = compare_versions(
            installed_version,
            expected_version,
        )

        if numeric_comparison is not None:
            if numeric_comparison != 0:
                return "no_match"
        elif (
            unicodedata.normalize("NFKC", installed_version).casefold()
            != unicodedata.normalize("NFKC", expected_version).casefold()
        ):
            return "no_match"

    # Compare any additional constrained CPE attributes.
    for attribute in (
        "update",
        "edition",
        "language",
        "sw_edition",
        "target_sw",
        "target_hw",
        "other",
    ):
        if parsed[f"{attribute}_is_wildcard"]:
            continue

        expected = parsed[attribute]
        actual = asset.get(attribute)

        if not isinstance(actual, str) or not actual:
            return "indeterminate"

        if normalize_name(actual) != normalize_name(expected):
            return "no_match"

    return "match"


def _evaluate_cpe_node(asset, node):
    """Evaluate one NVD configuration node against one asset."""
    if not isinstance(asset, dict) or not isinstance(node, dict):
        return {
            "result": "indeterminate",
            "vulnerable_match": False,
        }

    operator = node.get("operator")

    if not isinstance(operator, str):
        return {
            "result": "indeterminate",
            "vulnerable_match": False,
        }

    operator = operator.upper()

    if operator not in {"AND", "OR"}:
        return {
            "result": "indeterminate",
            "vulnerable_match": False,
        }

    if not isinstance(node.get("negate", False), bool):
        return {
            "result": "indeterminate",
            "vulnerable_match": False,
        }

    operands = []

    cpe_matches = node.get("cpeMatch", [])

    if not isinstance(cpe_matches, list):
        return {
            "result": "indeterminate",
            "vulnerable_match": False,
        }

    for cpe_match in cpe_matches:
        result = _evaluate_cpe_match(asset, cpe_match)

        vulnerable = (
            isinstance(cpe_match, dict)
            and cpe_match.get("vulnerable") is True
        )

        operands.append({
            "result": result,
            "vulnerable_match": result == "match" and vulnerable,
        })

    children = node.get("children", [])

    if not isinstance(children, list):
        return {
            "result": "indeterminate",
            "vulnerable_match": False,
        }

    for child in children:
        operands.append(_evaluate_cpe_node(asset, child))

    if not operands:
        return {
            "result": "indeterminate",
            "vulnerable_match": False,
        }

    combined = _combine_results(
        operator,
        [operand["result"] for operand in operands],
    )

    if node.get("negate", False):
        if combined == "match":
            combined = "no_match"
        elif combined == "no_match":
            combined = "match"

        return {
            "result": combined,
            "vulnerable_match": False,
        }

    vulnerable_match = (
        combined == "match"
        and any(
            operand["vulnerable_match"]
            for operand in operands
            if operand["result"] == "match"
        )
    )

    return {
        "result": combined,
        "vulnerable_match": vulnerable_match,
    }


def _evaluate_cpe_match_for_host(assets, cpe_match, inventory_complete=False):
    """Evaluate one CPE criterion against all assets belonging to one host."""
    if not isinstance(assets, list) or not isinstance(cpe_match, dict):
        return "indeterminate"

    if not isinstance(inventory_complete, bool):
        return "indeterminate"

    if any(not isinstance(asset, dict) for asset in assets):
        return "indeterminate"

    results = [
        _evaluate_cpe_match(asset, cpe_match)
        for asset in assets
    ]

    if "match" in results:
        return "match"

    if "indeterminate" in results or not inventory_complete:
        return "indeterminate"

    return "no_match"
