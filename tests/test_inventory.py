import csv
import tempfile
import unittest
from pathlib import Path

from core.inventory import (
    InventoryError,
    group_assets_by_host,
    load_inventory,
)


class TestInventoryLoader(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.csv_path = Path(self.temp_dir.name) / "inventory.csv"

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_csv(self, headers, rows):
        with self.csv_path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(rows)

    def test_loads_valid_inventory(self):
        self.write_csv(
            ["hostname", "part", "vendor", "product", "version"],
            [["server-01", "a", "Example Corp", "Widget", "2.1"]],
        )

        assets = load_inventory(self.csv_path)

        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["hostname"], "server-01")
        self.assertEqual(assets[0]["version"], "2.1")

    def test_allows_blank_version(self):
        self.write_csv(
            ["hostname", "part", "vendor", "product", "version"],
            [["server-01", "a", "Example Corp", "Widget", ""]],
        )

        assets = load_inventory(self.csv_path)

        self.assertEqual(assets[0]["version"], "")

    def test_preserves_optional_cpe_attributes(self):
        self.write_csv(
            [
                "hostname", "part", "vendor", "product", "version",
                "update",
            ],
            [["server-01", "a", "Example Corp", "Widget", "2.1", "SP1"]],
        )

        assets = load_inventory(self.csv_path)

        self.assertEqual(assets[0]["update"], "SP1")

    def test_rejects_missing_required_columns(self):
        self.write_csv(
            ["hostname", "vendor", "product", "version"],
            [["server-01", "Example Corp", "Widget", "2.1"]],
        )

        with self.assertRaises(InventoryError):
            load_inventory(self.csv_path)

    def test_rejects_invalid_part(self):
        self.write_csv(
            ["hostname", "part", "vendor", "product", "version"],
            [["server-01", "x", "Example Corp", "Widget", "2.1"]],
        )

        with self.assertRaises(InventoryError):
            load_inventory(self.csv_path)

    def test_rejects_blank_hostname(self):
        self.write_csv(
            ["hostname", "part", "vendor", "product", "version"],
            [["", "a", "Example Corp", "Widget", "2.1"]],
        )

        with self.assertRaises(InventoryError):
            load_inventory(self.csv_path)

    def test_groups_multiple_assets_by_hostname(self):
        assets = [
            {"hostname": "server-01", "product": "Widget"},
            {"hostname": "server-01", "product": "Linux"},
            {"hostname": "server-02", "product": "Widget"},
        ]

        hosts = group_assets_by_host(assets)

        self.assertEqual(len(hosts), 2)
        self.assertEqual(len(hosts["server-01"]), 2)
        self.assertEqual(len(hosts["server-02"]), 1)

    def test_rejects_invalid_grouping_input(self):
        with self.assertRaises(InventoryError):
            group_assets_by_host("invalid")


    def test_normalizes_whitespace_in_headers(self):
        self.write_csv(
            [" hostname ", " part ", " vendor ", " product ", " version "],
            [["server-01", "a", "Example Corp", "Widget", "2.1"]],
        )
        assets = load_inventory(self.csv_path)
        self.assertEqual(assets[0]["hostname"], "server-01")
        self.assertEqual(assets[0]["product"], "Widget")

    def test_rejects_extra_row_values(self):
        self.write_csv(
            ["hostname", "part", "vendor", "product", "version"],
            [["server-01", "a", "Example Corp", "Widget", "2.1", "unexpected"]],
        )
        with self.assertRaisesRegex(InventoryError, "more values"):
            load_inventory(self.csv_path)

    def test_rejects_blank_column_name(self):
        self.write_csv(
            ["hostname", "", "vendor", "product", "version"],
            [["server-01", "a", "Example Corp", "Widget", "2.1"]],
        )
        with self.assertRaisesRegex(InventoryError, "blank column"):
            load_inventory(self.csv_path)


if __name__ == "__main__":
    unittest.main()
