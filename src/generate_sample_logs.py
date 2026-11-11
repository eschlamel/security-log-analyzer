"""Generate reproducible, entirely synthetic authentication logs."""
import csv
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / 'data' / 'sample_auth_logs.csv'


def main():
    start = datetime(2026, 11, 11, 9, 0)
    rows = []
    for i in range(12):
        rows.append({'timestamp': (start + timedelta(minutes=i * 3)).isoformat(),
                     'username': 'employee1', 'source_ip': '192.0.2.18',
                     'status': 'success' if i % 4 else 'failure'})
    for i in range(8):
        rows.append({'timestamp': (start + timedelta(minutes=42, seconds=i * 25)).isoformat(),
                     'username': 'admin', 'source_ip': '198.51.100.45', 'status': 'failure'})
    rows.sort(key=lambda row: row['timestamp'])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open('w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=['timestamp', 'username', 'source_ip', 'status'])
        writer.writeheader()
        writer.writerows(rows)
    print(f'Created {len(rows)} synthetic events in {OUT}')


if __name__ == '__main__':
    main()
