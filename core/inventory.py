"""Load and validate customer asset inventories from CSV files."""

import csv
from pathlib import Path


REQUIRED_COLUMNS = (
    "hostname",
    "part",
    "vendor",
    "product",
    "version",
)

OPTIONAL_COLUMNS = (
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)

VALID_PARTS = {"a", "o", "h"}


class InventoryError(ValueError):
    """Raised when an asset inventory is invalid."""


def load_inventory(csv_path):
    """Load validated asset records from a customer CSV inventory."""
    path = Path(csv_path)

    try:
        with path.open("r", encoding="utf-8-sig", newline="") as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames:
                raise InventoryError("Inventory CSV is empty or has no header.")

            headers = [header.strip() for header in reader.fieldnames]

            if any(not header for header in headers):
                raise InventoryError("Inventory CSV contains a blank column name.")

            if len(headers) != len(set(headers)):
                raise InventoryError("Inventory CSV contains duplicate columns.")

            reader.fieldnames = headers

            missing = [
                column for column in REQUIRED_COLUMNS
                if column not in headers
            ]

            if missing:
                raise InventoryError(
                    "Missing required columns: " + ", ".join(missing)
                )

            assets = []

            for row in reader:
                row_number = reader.line_num

                if None in row:
                    raise InventoryError(
                        f"Row {row_number}: contains more values than header columns."
                    )

                if not row or all(
                    not str(value or "").strip()
                    for value in row.values()
                ):
                    continue

                asset = {
                    str(key).strip(): str(value or "").strip()
                    for key, value in row.items()
                    if key is not None
                }

                for field in ("hostname", "vendor", "product"):
                    if not asset.get(field):
                        raise InventoryError(
                            f"Row {row_number}: '{field}' cannot be blank."
                        )

                part = asset.get("part", "").lower()

                if part not in VALID_PARTS:
                    raise InventoryError(
                        f"Row {row_number}: part must be a, o, or h."
                    )

                asset["part"] = part

                for field in OPTIONAL_COLUMNS:
                    if not asset.get(field):
                        asset.pop(field, None)

                assets.append(asset)

            if not assets:
                raise InventoryError(
                    "Inventory contains no valid asset records."
                )

            return assets

    except InventoryError:
        raise
    except (OSError, UnicodeError, csv.Error) as exc:
        raise InventoryError(
            f"Could not read inventory CSV: {exc}"
        ) from exc


def group_assets_by_host(assets):
    """Group validated asset records by hostname."""
    if not isinstance(assets, list):
        raise InventoryError("Assets must be supplied as a list.")

    hosts = {}

    for index, asset in enumerate(assets, start=1):
        if not isinstance(asset, dict):
            raise InventoryError(
                f"Asset {index} must be a dictionary."
            )

        hostname = asset.get("hostname")

        if not isinstance(hostname, str) or not hostname.strip():
            raise InventoryError(
                f"Asset {index} has no valid hostname."
            )

        hosts.setdefault(hostname.strip(), []).append(asset)

    return hosts
