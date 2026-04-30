#!/usr/bin/env python3
"""
Honeypot Performance Metrics Analyzer

This script analyzes the performance metrics of your honeypot application
by querying the Django database and displaying key performance indicators.

Usage: python performance_analyzer.py
"""

import os
import sys
import django
from datetime import datetime, timedelta
from django.db.models import Count, Avg, Min, Max

# Setup Django
sys.path.append(os.path.dirname(__file__))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Honeypot.settings')
django.setup()

from HoneypotApp.models import RequestEvent, AttackerProfile, AttackLabel

def format_duration(ms):
    """Format milliseconds into human readable duration"""
    if ms < 1000:
        return f"{ms}ms"
    elif ms < 60000:
        return f"{ms/1000:.2f}s"
    else:
        return f"{ms/60000:.2f}min"

def analyze_performance():
    """Analyze and display performance metrics"""
    print("=" * 60)
    print("HONEYPOT PERFORMANCE METRICS ANALYZER")
    print("=" * 60)

    try:
        # Basic counts
        total_requests = RequestEvent.objects.count()
        active_attackers = AttackerProfile.objects.count()

        if total_requests == 0:
            print("No request data found in the database.")
            print("The honeypot may not have received any traffic yet.")
            return

        # Response time analysis
        duration_stats = RequestEvent.objects.filter(duration_ms__isnull=False).aggregate(
            count=Count('duration_ms'),
            avg_time=Avg('duration_ms'),
            min_time=Min('duration_ms'),
            max_time=Max('duration_ms')
        )

        # Percentiles
        durations = list(RequestEvent.objects.filter(duration_ms__isnull=False)
                        .order_by('duration_ms')
                        .values_list('duration_ms', flat=True))

        if durations:
            p50 = durations[len(durations)//2]
            p95 = durations[int(len(durations)*0.95)] if len(durations) > 1 else durations[0]
            p99 = durations[int(len(durations)*0.99)] if len(durations) > 1 else durations[0]
        else:
            p50 = p95 = p99 = 0

        # Time-based analysis
        time_range = RequestEvent.objects.aggregate(
            first=Min('created_at'),
            last=Max('created_at')
        )

        if time_range['first'] and time_range['last']:
            total_seconds = (time_range['last'] - time_range['first']).total_seconds()
            total_minutes = total_seconds / 60
            total_hours = total_seconds / 3600

            rpm = total_requests / max(1, total_minutes)
            rph = total_requests / max(1, total_hours)
        else:
            rpm = rph = 0

        # Recent activity (last hour)
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent_requests = RequestEvent.objects.filter(created_at__gte=one_hour_ago).count()

        # Status code distribution
        status_codes = (RequestEvent.objects.filter(status_code__isnull=False)
                       .values('status_code')
                       .annotate(count=Count('status_code'))
                       .order_by('-count')[:10])

        # Attack type distribution
        attack_types = (AttackLabel.objects
                       .values('attack_type')
                       .annotate(count=Count('attack_type'))
                       .order_by('-count')[:5])

        # Display results
        print(f"\n📊 OVERVIEW")
        print(f"Total Requests Processed: {total_requests:,}")
        print(f"Active Attacker Profiles: {active_attackers:,}")
        print(f"Data Collection Period: {total_hours:.1f} hours")

        print(f"\n⚡ RESPONSE TIME METRICS")
        print(f"Average Response Time: {format_duration(duration_stats['avg_time'] or 0)}")
        print(f"Minimum Response Time: {format_duration(duration_stats['min_time'] or 0)}")
        print(f"Maximum Response Time: {format_duration(duration_stats['max_time'] or 0)}")
        print(f"50th Percentile (P50): {format_duration(p50)}")
        print(f"95th Percentile (P95): {format_duration(p95)}")
        print(f"99th Percentile (P99): {format_duration(p99)}")

        print(f"\n📈 REQUEST RATES")
        print(f"Average Requests/Minute: {rpm:.2f}")
        print(f"Average Requests/Hour: {rph:.2f}")
        print(f"Requests in Last Hour: {recent_requests}")

        print(f"\n🔍 HTTP STATUS CODES")
        for status in status_codes:
            percentage = (status['count'] / total_requests) * 100
            print(f"  {status['status_code']}: {status['count']:,} requests ({percentage:.1f}%)")

        if attack_types:
            print(f"\n🛡️ DETECTED ATTACK TYPES")
            for attack in attack_types:
                percentage = (attack['count'] / total_requests) * 100
                print(f"  {attack['attack_type']}: {attack['count']:,} detections ({percentage:.1f}%)")

        print(f"\n💡 PERFORMANCE INSIGHTS")
        if duration_stats['avg_time'] and duration_stats['avg_time'] > 1000:
            print("⚠️  Average response time is high (>1s) - consider optimizing")
        elif duration_stats['avg_time'] and duration_stats['avg_time'] < 100:
            print("✅ Fast response times detected")

        if rpm > 10:
            print("🚨 High request rate detected - heavy traffic or attack")
        elif rpm < 1:
            print("📉 Low request rate - light traffic")

        if p95 > 5000:
            print("⚠️  Some requests are very slow (P95 > 5s)")

        print(f"\n" + "=" * 60)
        print("Analysis completed successfully!")
        print("View live metrics at: http://127.0.0.1:8000/system-status/")
        print("=" * 60)

    except Exception as e:
        print(f"Error analyzing performance: {e}")
        print("Make sure the database is accessible and contains data.")

if __name__ == "__main__":
    analyze_performance()