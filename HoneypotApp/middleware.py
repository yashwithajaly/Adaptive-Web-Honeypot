import time
import json
from datetime import datetime, timedelta
from django.utils import timezone
from HoneypotApp.detector import detect_attack
from HoneypotApp.profiler import profile_attacker
from HoneypotApp.llm_analyzer import analyze_with_llm
from HoneypotApp.models import AttackSession, RequestEvent, AttackLabel, AttackerProfile

MAX_TEXT = 20000
SESSION_WINDOW_MINUTES = 30


def _safe_text(x):
    s = str(x) if x is not None else ""
    return s[:MAX_TEXT]


def _get_ip(request):
    return request.META.get("REMOTE_ADDR", "")


def _get_or_create_session(ip, ua):
    now = timezone.now()
    cutoff = now - timedelta(minutes=SESSION_WINDOW_MINUTES)

    # Try to find existing session
    session = AttackSession.objects.filter(
        ip_address=ip,
        user_agent=ua,
        last_seen__gte=cutoff
    ).order_by('-last_seen').first()

    if session:
        session.last_seen = now
        session.request_count += 1
        session.save()
        return session

    # Create new session
    session = AttackSession.objects.create(
        ip_address=ip,
        user_agent=ua,
        start_time=now,
        last_seen=now,
        request_count=1
    )
    return session


def _update_attacker_profile(session, ip):
    """Update attacker profile based on session statistics"""
    # Get session stats
    request_events = RequestEvent.objects.filter(session=session)
    first_time = request_events.order_by('created_at').first().created_at if request_events.exists() else timezone.now()
    last_time = request_events.order_by('-created_at').first().created_at if request_events.exists() else timezone.now()
    req_count = request_events.count()
    distinct_paths = request_events.values('path').distinct().count()

    duration_sec = max(1, int((last_time - first_time).total_seconds()))

    # Get attack counts
    attack_labels = AttackLabel.objects.filter(request__session=session)
    attack_counts = {}
    for label in attack_labels:
        attack_counts[label.attack_type] = attack_counts.get(label.attack_type, 0) + 1

    stats = {
        "request_count": req_count,
        "duration_sec": duration_sec,
        "distinct_paths": distinct_paths,
        "attack_counts": attack_counts
    }

    bot, skill, notes = profile_attacker(stats)

    # Update or create attacker profile
    AttackerProfile.objects.update_or_create(
        ip_address=ip,
        defaults={
            'bot_or_human': bot,
            'skill_level': skill,
            'behavior_notes': notes
        }
    )


class AttackLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start = time.time()

        ip = _get_ip(request)
        method = request.method
        path = request.path
        qs = request.META.get("QUERY_STRING", "")
        ua = request.META.get("HTTP_USER_AGENT", "")
        referer = request.META.get("HTTP_REFERER", "")

        headers = {
            k: v for k, v in request.META.items()
            if k.startswith("HTTP_") and k != "HTTP_COOKIE"
        }

        payload = dict(request.POST) if method == "POST" else dict(request.GET)

        headers_text = _safe_text(json.dumps(headers))
        payload_text = _safe_text(json.dumps(payload))

        response = self.get_response(request)
        status_code = getattr(response, "status_code", None)
        duration_ms = int((time.time() - start) * 1000)

        try:
            session = _get_or_create_session(ip, ua)

            # Create request event
            request_event = RequestEvent.objects.create(
                session=session,
                ip_address=ip,
                method=method,
                path=path,
                query_string=qs,
                headers_text=headers_text,
                payload_text=payload_text,
                user_agent=ua,
                referer=referer,
                status_code=status_code,
                duration_ms=duration_ms
            )

            # Rule-based detection
            rule_type, rule_conf, rule_summary = detect_attack(payload_text, path, method)
            if rule_type:  # Only create if there's a detection
                AttackLabel.objects.create(
                    request=request_event,
                    attack_type=rule_type,
                    intent_summary=rule_summary,
                    confidence=rule_conf
                )

            # LLM analysis (updates final label if different)
            ai_type, ai_summary, ai_conf = analyze_with_llm(payload_text, path, method)
            if ai_type and ai_type != rule_type:
                AttackLabel.objects.filter(request=request_event).update(
                    attack_type=ai_type,
                    intent_summary=ai_summary,
                    confidence=ai_conf
                )

            # Profiling stats and attacker profile update
            _update_attacker_profile(session, ip)

        except Exception as e:
            print("MIDDLEWARE ERROR:", e)

        return response