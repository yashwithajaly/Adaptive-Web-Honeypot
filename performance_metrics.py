import pymysql
import json
from datetime import datetime, timedelta

def get_db_connection():
    return pymysql.connect(
        host='127.0.0.1',
        user='root',
        password='root',
        database='honeypot_db',
        port=3306,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

try:
    conn = get_db_connection()
    with conn.cursor() as cur:
        # Total requests
        cur.execute('SELECT COUNT(*) as total FROM request_event')
        total_requests = cur.fetchone()['total']

        # Average response time
        cur.execute('SELECT AVG(duration_ms) as avg_time FROM request_event WHERE duration_ms IS NOT NULL')
        avg_time = cur.fetchone()['avg_time'] or 0

        # Min/Max response time
        cur.execute('SELECT MIN(duration_ms) as min_time, MAX(duration_ms) as max_time FROM request_event WHERE duration_ms IS NOT NULL')
        time_stats = cur.fetchone()
        min_time = time_stats['min_time'] or 0
        max_time = time_stats['max_time'] or 0

        # Requests in last hour
        one_hour_ago = datetime.now() - timedelta(hours=1)
        cur.execute('SELECT COUNT(*) as recent FROM request_event WHERE created_at >= %s', (one_hour_ago,))
        recent_requests = cur.fetchone()['recent']

        # Status code distribution
        cur.execute('SELECT status_code, COUNT(*) as count FROM request_event WHERE status_code IS NOT NULL GROUP BY status_code ORDER BY count DESC')
        status_codes = cur.fetchall()

        # Response time percentiles
        cur.execute('SELECT duration_ms FROM request_event WHERE duration_ms IS NOT NULL ORDER BY duration_ms')
        durations = [row['duration_ms'] for row in cur.fetchall()]

        if durations:
            p50 = durations[len(durations)//2]
            p95 = durations[int(len(durations)*0.95)] if len(durations) > 1 else durations[0]
            p99 = durations[int(len(durations)*0.99)] if len(durations) > 1 else durations[0]
        else:
            p50 = p95 = p99 = 0

    print('=== PERFORMANCE METRICS ===')
    print(f'Total Requests: {total_requests}')
    print(f'Average Response Time: {avg_time:.2f} ms')
    print(f'Min Response Time: {min_time} ms')
    print(f'Max Response Time: {max_time} ms')
    print(f'50th Percentile: {p50} ms')
    print(f'95th Percentile: {p95} ms')
    print(f'99th Percentile: {p99} ms')
    print(f'Requests in Last Hour: {recent_requests}')

    # Calculate requests per minute based on data timeframe
    if total_requests > 0:
        cur.execute('SELECT MIN(created_at) as first, MAX(created_at) as last FROM request_event')
        time_range = cur.fetchone()
        if time_range['first'] and time_range['last']:
            total_minutes = (time_range['last'] - time_range['first']).total_seconds() / 60
            rpm = total_requests / max(1, total_minutes)
            print(f'Average Requests per Minute: {rpm:.2f}')
        else:
            print('Average Requests per Minute: N/A (no time data)')

    print('\n=== STATUS CODE DISTRIBUTION ===')
    for status in status_codes:
        print(f'{status["status_code"]}: {status["count"]} requests')

    conn.close()

except Exception as e:
    print(f"Error: {e}")
    print("Make sure the database is running and accessible.")