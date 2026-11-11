"""Find IP addresses with bursts of failed authentication attempts."""
import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

INPUT = Path(__file__).resolve().parents[1] / 'data' / 'sample_auth_logs.csv'


def detect_failed_login_bursts(events, threshold=5, window_minutes=5):
    """Return one alert per IP when its failures first reach threshold in the window."""
    failures = defaultdict(deque)
    alerts = []
    alerted_ips = set()
    for event in sorted(events, key=lambda item: item['timestamp']):
        if event['status'].lower() != 'failure':
            continue
        ip = event['source_ip']
        moment = datetime.fromisoformat(event['timestamp'])
        queue = failures[ip]
        queue.append(moment)
        cutoff = moment - timedelta(minutes=window_minutes)
        while queue and queue[0] < cutoff:
            queue.popleft()
        if len(queue) >= threshold and ip not in alerted_ips:
            alerts.append({'source_ip': ip, 'timestamp': event['timestamp'],
                           'failed_attempts': len(queue)})
            alerted_ips.add(ip)
    return alerts


def detect_after_hours_logins(events, start_hour=8, end_hour=18):
    """Identify successful logins outside normal business hours."""
    alerts = []

    for event in events:
        if event['status'].lower() != 'success':
            continue

        moment = datetime.fromisoformat(event['timestamp'])

        if moment.hour < start_hour or moment.hour >= end_hour:
            alerts.append({
                'source_ip': event['source_ip'],
                'timestamp': event['timestamp'],
                'alert_type': 'After-hours login'
            })

    return alerts



def main():
    if not INPUT.exists():
        print('No sample logs found. Run: python3 src/generate_sample_logs.py')
        return

    with INPUT.open(newline='', encoding='utf-8') as file:
        events = list(csv.DictReader(file))

    # Detection Rule 1: Repeated failed logins
    brute_force_alerts = detect_failed_login_bursts(events)

    # Detection Rule 2: Successful logins after hours
    after_hours_alerts = detect_after_hours_logins(events)

    total_alerts = len(brute_force_alerts) + len(after_hours_alerts)

    print(f'Analyzed {len(events)} events.')
    print(f'Found {total_alerts} security alert(s).')

    for alert in brute_force_alerts:
        print(
            f"BRUTE FORCE ALERT: {alert['source_ip']} had "
            f"{alert['failed_attempts']} failed logins within 5 minutes."
        )

    for alert in after_hours_alerts:
        print(
            f"AFTER-HOURS ALERT: Successful login from "
            f"{alert['source_ip']} at {alert['timestamp']}"
        )


if __name__ == '__main__':
    main()
