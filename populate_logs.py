import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
RECORDS_DIR = BASE_DIR / "records"
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0",
    "CyberGuard-Monitor/1.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/17.6",
)
REQUESTS = (
    "GET /api/v1/health HTTP/1.1",
    "GET /api/v1/audit/events HTTP/1.1",
    "POST /api/v1/auth/session HTTP/1.1",
    "GET /api/v1/records/export HTTP/1.1",
    "GET /api/v1/config HTTP/1.1",
)


def create_record(index):
    timestamp = (
        datetime(2026, 10, 1, tzinfo=timezone.utc) + timedelta(minutes=index * 7)
    ).isoformat(timespec="seconds")
    ip_address = f"192.0.2.{(index % 200) + 1}"
    request_line = REQUESTS[(index - 1) % len(REQUESTS)]
    status_code = (200, 200, 200, 304, 401, 403)[(index - 1) % 6]
    bytes_transferred = 256 + (index * 137) % 8192
    user_agent = USER_AGENTS[(index - 1) % len(USER_AGENTS)]
    classification = (
        "RESTRICTED" if status_code in (401, 403)
        else "CONFIDENTIAL" if "records" in request_line or "config" in request_line
        else "INTERNAL"
    )
    fields = (
        f"ip={ip_address}",
        f"timestamp={timestamp}",
        f'http_request_line="{request_line}"',
        f"status_code={status_code}",
        f"bytes_transferred={bytes_transferred}",
        f'user_agent="{user_agent}"',
        f"classification_level={classification}",
    )
    signature = hashlib.sha256("\n".join(fields).encode("utf-8")).hexdigest()
    return "\n".join((*fields, f"integrity_signature=sha256:{signature}")) + "\n"


def main():
    RECORDS_DIR.mkdir(parents=True, exist_ok=True)
    for record_number in range(1, 101):
        record_path = RECORDS_DIR / f"record_{record_number}.txt"
        record_path.write_text(create_record(record_number), encoding="utf-8")
    print(f"Generated 100 structured server log records in {RECORDS_DIR}.")


if __name__ == "__main__":
    main()
