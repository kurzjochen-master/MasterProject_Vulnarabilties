"""Download raw CVE data from the NVD CVE API 2.0."""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from datetime import date, datetime, time as datetime_time, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import requests
from dotenv import load_dotenv
from tqdm import tqdm


API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RESULTS_PER_PAGE = 2_000
MAX_DATE_RANGE_DAYS = 120
OUTPUT_DIR = Path("data/raw/nvd")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Download raw CVE records from the NVD CVE API 2.0."
    )
    parser.add_argument(
        "--start-date",
        required=True,
        help="Start date for published CVEs, e.g. 2024-01-01 or 2024-01-01T00:00:00.",
    )
    parser.add_argument(
        "--end-date",
        required=True,
        help="End date for published CVEs, e.g. 2024-01-31 or 2024-01-31T23:59:59.",
    )
    parser.add_argument(
        "--results-per-page",
        type=int,
        default=DEFAULT_RESULTS_PER_PAGE,
        help=f"Number of results per page, max {DEFAULT_RESULTS_PER_PAGE}.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=OUTPUT_DIR,
        help="Directory for raw JSON responses.",
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


def parse_date_argument(value: str, *, end_of_day: bool) -> datetime:
    """Convert a CLI date value to a timezone-aware UTC datetime."""
    try:
        parsed_datetime = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        parsed_date = date.fromisoformat(value)
        selected_time = datetime_time.max if end_of_day else datetime_time.min
        parsed_datetime = datetime.combine(parsed_date, selected_time)

    if parsed_datetime.tzinfo is None:
        return parsed_datetime.replace(tzinfo=timezone.utc)

    return parsed_datetime.astimezone(timezone.utc)


def format_nvd_datetime(value: datetime) -> str:
    """Format a datetime for NVD API date parameters."""
    utc_value = value.astimezone(timezone.utc)
    return utc_value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23]


def iter_date_windows(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    """Yield NVD-compatible date windows."""
    current_start = start
    max_delta = timedelta(days=MAX_DATE_RANGE_DAYS)

    while current_start <= end:
        current_end = min(current_start + max_delta, end)
        yield current_start, current_end
        current_start = current_end + timedelta(milliseconds=1)


def build_headers() -> dict[str, str]:
    """Build request headers, including an optional API key."""
    headers = {"User-Agent": "masterproject-vulnerabilities-nvd-fetcher/1.0"}
    api_key = os.getenv("NVD_API_KEY")

    if api_key:
        headers["apiKey"] = api_key

    return headers


def fetch_page(
    session: requests.Session,
    headers: dict[str, str],
    window_start: datetime,
    window_end: datetime,
    start_index: int,
    results_per_page: int,
) -> dict[str, Any]:
    """Fetch one paginated NVD API response."""
    params = {
        "pubStartDate": format_nvd_datetime(window_start),
        "pubEndDate": format_nvd_datetime(window_end),
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }

    response = session.get(API_URL, params=params, headers=headers, timeout=60)
    response.raise_for_status()
    return response.json()


def save_raw_response(
    payload: dict[str, Any],
    output_dir: Path,
    window_number: int,
    start_index: int,
) -> Path:
    """Persist one raw API response as JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)
    file_path = output_dir / f"nvd_window_{window_number:03d}_start_{start_index:07d}.json"

    with file_path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, ensure_ascii=False, indent=2)

    return file_path


def download_nvd_data(
    start: datetime,
    end: datetime,
    output_dir: Path,
    results_per_page: int,
) -> None:
    """Download all matching raw NVD API pages."""
    if start > end:
        raise ValueError("--start-date must be before or equal to --end-date.")

    if not 1 <= results_per_page <= DEFAULT_RESULTS_PER_PAGE:
        raise ValueError(f"--results-per-page must be between 1 and {DEFAULT_RESULTS_PER_PAGE}.")

    headers = build_headers()
    delay_seconds = 0.6 if "apiKey" in headers else 6.0
    total_records = 0
    total_files = 0

    logging.info("Downloading NVD CVE data from %s to %s", start.isoformat(), end.isoformat())
    logging.info("Writing raw JSON responses to %s", output_dir)

    with requests.Session() as session:
        for window_number, (window_start, window_end) in enumerate(
            iter_date_windows(start, end), start=1
        ):
            logging.info(
                "Fetching window %s: %s to %s",
                window_number,
                format_nvd_datetime(window_start),
                format_nvd_datetime(window_end),
            )

            start_index = 0
            total_results: int | None = None

            with tqdm(desc=f"NVD window {window_number}", unit="page") as progress_bar:
                while total_results is None or start_index < total_results:
                    payload = fetch_page(
                        session=session,
                        headers=headers,
                        window_start=window_start,
                        window_end=window_end,
                        start_index=start_index,
                        results_per_page=results_per_page,
                    )

                    total_results = int(payload.get("totalResults", 0))
                    returned_results = int(payload.get("resultsPerPage", 0))
                    saved_file = save_raw_response(
                        payload=payload,
                        output_dir=output_dir,
                        window_number=window_number,
                        start_index=start_index,
                    )

                    total_records += len(payload.get("vulnerabilities", []))
                    total_files += 1
                    logging.info("Saved %s", saved_file)
                    progress_bar.update(1)

                    if returned_results <= 0:
                        break

                    start_index += returned_results

                    if start_index < total_results:
                        time.sleep(delay_seconds)

    logging.info("Download complete: %s records across %s files.", total_records, total_files)


def main() -> None:
    """Run the NVD downloader."""
    load_dotenv()
    args = parse_args()
    configure_logging(args.log_level)

    start = parse_date_argument(args.start_date, end_of_day=False)
    end = parse_date_argument(args.end_date, end_of_day=True)

    download_nvd_data(
        start=start,
        end=end,
        output_dir=args.output_dir,
        results_per_page=args.results_per_page,
    )


if __name__ == "__main__":
    main()
