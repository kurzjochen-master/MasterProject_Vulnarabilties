"""Inspect raw NVD JSON files without modifying them."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any


DEFAULT_INPUT_DIR = Path("data/raw/nvd")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Check raw NVD JSON files and summarize pagination metadata."
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help="Directory containing raw NVD JSON files.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="Logging verbosity.",
    )
    return parser.parse_args()


def configure_logging(log_level: str) -> None:
    """Configure console logging."""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )


def load_json_file(file_path: Path) -> dict[str, Any]:
    """Read a raw NVD JSON file."""
    with file_path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, dict):
        raise ValueError(f"{file_path} does not contain a JSON object.")

    return payload


def check_file(file_path: Path) -> int:
    """Log pagination metadata for one raw NVD JSON file."""
    payload = load_json_file(file_path)
    vulnerabilities = payload.get("vulnerabilities", [])

    if not isinstance(vulnerabilities, list):
        raise ValueError(f"{file_path} has no valid vulnerabilities list.")

    start_index = payload.get("startIndex")
    results_per_page = payload.get("resultsPerPage")
    total_results = payload.get("totalResults")
    vulnerability_count = len(vulnerabilities)

    logging.info(
        (
            "file=%s startIndex=%s resultsPerPage=%s totalResults=%s "
            "vulnerabilities=%s"
        ),
        file_path.name,
        start_index,
        results_per_page,
        total_results,
        vulnerability_count,
    )

    if vulnerability_count == results_per_page:
        logging.info(
            "Pagination check passed for %s: len(vulnerabilities) == resultsPerPage",
            file_path.name,
        )
    else:
        logging.warning(
            (
                "Pagination check differs for %s: len(vulnerabilities)=%s, "
                "resultsPerPage=%s"
            ),
            file_path.name,
            vulnerability_count,
            results_per_page,
        )

    return vulnerability_count


def check_raw_nvd_files(input_dir: Path) -> None:
    """Check all raw NVD JSON files in a directory."""
    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir}")

    json_files = sorted(input_dir.glob("*.json"))

    if not json_files:
        logging.warning("No JSON files found in %s", input_dir)
        logging.info("Total vulnerabilities: 0")
        return

    logging.info("Checking %s JSON files in %s", len(json_files), input_dir)

    total_vulnerabilities = 0
    for file_path in json_files:
        total_vulnerabilities += check_file(file_path)

    logging.info("Total vulnerabilities: %s", total_vulnerabilities)


def main() -> None:
    """Run the raw NVD data check."""
    args = parse_args()
    configure_logging(args.log_level)
    check_raw_nvd_files(args.input_dir)


if __name__ == "__main__":
    main()
