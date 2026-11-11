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


def main():
    if not INPUT.exists():
        print('No sample logs found. Run: python src/generate_sample_logs.py')
        return
    with INPUT.open(newline='', encoding='utf-8') as file:
        events = list(csv.DictReader(file))
    alerts = detect_failed_login_bursts(events)
    print(f'Analyzed {len(events)} events. Found {len(alerts)} alert(s).')
    for alert in alerts:
        print(f"ALERT: {alert['source_ip']} had {alert['failed_attempts']} failed logins within 5 minutes at {alert['timestamp']}")


if __name__ == '__main__':
    main()
