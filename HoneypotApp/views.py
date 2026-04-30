import time
import random
from django.utils import timezone
from django.db.models import Count, Avg, Min, Max
from HoneypotApp.models import RequestEvent, AttackerProfile, AttackLabel
from django.shortcuts import render, redirect

# =========================
# SIMPLE ATTACK DETECTOR
# =========================
def detect_attack_type(payload_text, path=""):
    text = (payload_text or "").lower()
    path = (path or "").lower()

    if any(x in text for x in ["' or 1=1", "union select", "admin'--", "' or '1'='1", "--", "#"]):
        return "SQL Injection", 0.95

    if any(x in text for x in ["<script>", "onerror=", "<img", "alert("]):
        return "XSS", 0.95

    if any(x in text for x in ["; ls", "; cat", "&&", "||", "cmd", "/bin/sh"]):
        return "Command Injection", 0.90

    if "admin" in text and any(x in text for x in ["123", "admin", "test", "password"]):
        return "Brute Force", 0.80

    if "bot" in text:
        return "Bot Activity", 0.75

    if any(x in path for x in ["wp-login.php", "phpmyadmin", ".env", "backup.zip"]):
        return "Reconnaissance", 0.70

    return "Unknown", 0.30


# =========================
# SIMPLE ATTACK PROFILER
# =========================
def update_attacker_profile(ip, attack_type, user_agent=""):
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, behavior_notes FROM attacker_profile WHERE ip_address=%s",
                (ip,)
            )
            row = cur.fetchone()

            if attack_type in ["SQL Injection", "XSS", "Command Injection"]:
                skill_level = "High"
            elif attack_type in ["Brute Force", "Bot Activity", "Reconnaissance"]:
                skill_level = "Medium"
            else:
                skill_level = "Low"

            bot_or_human = "Bot" if "bot" in (user_agent or "").lower() else "Human"

            if row:
                old_notes = row.get("behavior_notes") or ""
                if attack_type != "Unknown" and attack_type not in old_notes:
                    new_notes = old_notes + (", " if old_notes else "") + attack_type
                else:
                    new_notes = old_notes

                cur.execute("""
                    UPDATE attacker_profile
                    SET bot_or_human=%s,
                        skill_level=%s,
                        behavior_notes=%s,
                        updated_at=NOW()
                    WHERE ip_address=%s
                """, (bot_or_human, skill_level, new_notes, ip))
            else:
                cur.execute("""
                    INSERT INTO attacker_profile
                    (ip_address, bot_or_human, skill_level, behavior_notes, updated_at)
                    VALUES (%s, %s, %s, %s, NOW())
                """, (ip, bot_or_human, skill_level, attack_type))

        conn.close()
    except Exception as e:
        print("PROFILE UPDATE ERROR:", e)


# =========================
# LOGGING (RECORDER)
# =========================
MAX_BODY_CHARS = 20000  # prevent DB spam

def log_request_event(request, start_time=None):
    """
    Logs attacker activity and updates attack labels + attacker profile.
    Requires MySQL tables:
    - request_event
    - attack_label
    - attacker_profile
    """
    try:
        ip = request.META.get("REMOTE_ADDR", "")
        method = request.method
        path = request.path
        qs = request.META.get("QUERY_STRING", "")
        ua = request.META.get("HTTP_USER_AGENT", "")
        referer = request.META.get("HTTP_REFERER", "")

        if method == "POST":
            payload = str(dict(request.POST))
        else:
            payload = str(dict(request.GET))

        payload = payload[:MAX_BODY_CHARS]

        duration_ms = None
        if start_time is not None:
            duration_ms = int((time.time() - start_time) * 1000)

        conn = get_db_connection()
        with conn.cursor() as cursor:
            # 1. Insert request log
            cursor.execute(
                """
                INSERT INTO request_event
                (ip_address, method, path, query_string, payload_text, user_agent, referer, duration_ms)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (ip, method, path, qs, payload, ua, referer, duration_ms)
            )
            request_id = cursor.lastrowid

            # 2. Detect attack type
            attack_type, confidence = detect_attack_type(payload, path)

            # 3. Save attack label
            cursor.execute(
                """
                INSERT IGNORE INTO attack_label
                (request_id, attack_type, intent_summary, confidence)
                VALUES (%s,%s,%s,%s)
                """,
                (
                    request_id,
                    attack_type,
                    f"Detected from payload/path: {attack_type}",
                    confidence
                )
            )

        conn.close()

        # 4. Update attacker profile only if not unknown
        if attack_type != "Unknown":
            update_attacker_profile(ip, attack_type, ua)

    except Exception as e:
        print("LOG ERROR:", e)


# =========================
# PUBLIC PAGES
# =========================
def home(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)
    return render(request, "home.html")


# =========================
# USER LOGIN -> BANKING HONEYPOT
# =========================
def fake_login(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    msg = ""

    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")

        # store attacker session
        request.session["honeypot_user"] = username if username else "guest_user"

        # always allow entry into fake banking portal
        outcome = "success"

        if outcome == "fail":
            msg = "Invalid username or password."
        elif outcome == "locked":
            msg = "Account temporarily locked due to suspicious activity."
        else:
            return redirect("bank_dashboard")

    return render(request, "login.html", {"message": msg})


# =========================
# FAKE BANK DASHBOARD
# =========================
def bank_dashboard(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    if not request.session.get("honeypot_user"):
        return redirect("fake_login")

    data = {
        "customer_name": request.session.get("honeypot_user", "Guest User"),
        "account_no": "458712349876",
        "ifsc": "SBIN0004587",
        "branch": "Hyderabad Main Branch",
        "balance": random.randint(50000, 500000),
        "loan_offer": random.randint(100000, 900000),
        "card_type": "Visa Platinum",
        "last_login": "27-03-2026 10:15 AM"
    }
    return render(request, "bank_dashboard.html", data)


# =========================
# ACCOUNT SUMMARY
# =========================
def account_summary(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    if not request.session.get("honeypot_user"):
        return redirect("fake_login")

    summary = {
        "name": request.session.get("honeypot_user", "Guest User"),
        "account_no": "458712349876",
        "account_type": "Savings Account",
        "available_balance": random.randint(60000, 350000),
        "email": "support@securebank.com",
        "mobile": "+91 9XXXXXXXXX",
        "branch": "Hyderabad Main Branch",
        "kyc_status": "Verified"
    }
    return render(request, "account_summary.html", summary)


# =========================
# TRANSFER MONEY
# =========================
def transfer_money(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    if not request.session.get("honeypot_user"):
        return redirect("fake_login")

    msg = ""
    if request.method == "POST":
        beneficiary = request.POST.get("beneficiary", "")
        account_number = request.POST.get("account_number", "")
        amount = request.POST.get("amount", "")
        remarks = request.POST.get("remarks", "")

        ref_no = "TXN" + str(random.randint(100000, 999999))
        msg = f"Transaction successful. Reference No: {ref_no}"

    return render(request, "transfer_money.html", {"message": msg})


# =========================
# TRANSACTION HISTORY
# =========================
def transaction_history(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    if not request.session.get("honeypot_user"):
        return redirect("fake_login")

    transactions = [
        {"date": "25-03-2026", "desc": "ATM Withdrawal", "type": "Debit", "amount": 5000, "status": "Success"},
        {"date": "24-03-2026", "desc": "Salary Credit", "type": "Credit", "amount": 45000, "status": "Success"},
        {"date": "22-03-2026", "desc": "UPI Transfer", "type": "Debit", "amount": 2200, "status": "Success"},
        {"date": "20-03-2026", "desc": "Electricity Bill", "type": "Debit", "amount": 1850, "status": "Success"},
        {"date": "18-03-2026", "desc": "NEFT Received", "type": "Credit", "amount": 12000, "status": "Success"},
    ]
    return render(request, "transaction_history.html", {"transactions": transactions})


# =========================
# BENEFICIARY PAGE
# =========================
def beneficiary_page(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    if not request.session.get("honeypot_user"):
        return redirect("fake_login")

    msg = ""
    if request.method == "POST":
        ben_name = request.POST.get("beneficiary_name", "")
        bank_name = request.POST.get("bank_name", "")
        account_number = request.POST.get("account_number", "")

        msg = "Beneficiary added successfully and will be activated within 30 minutes."

    beneficiaries = [
        {"name": "Ramesh Kumar", "bank": "HDFC Bank", "account": "XXXXXX2345"},
        {"name": "Suresh Naidu", "bank": "ICICI Bank", "account": "XXXXXX8890"},
        {"name": "Anil Sharma", "bank": "Axis Bank", "account": "XXXXXX1134"},
    ]
    return render(request, "beneficiary.html", {"beneficiaries": beneficiaries, "message": msg})


# =========================
# CARD SERVICES
# =========================
def card_services(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    if not request.session.get("honeypot_user"):
        return redirect("fake_login")

    card = {
        "card_number": "4111 78XX XXXX 9087",
        "card_type": "Visa Platinum",
        "expiry": "09/29",
        "status": "Active",
        "limit": "₹ 2,00,000",
        "cvv_hint": "***"
    }
    return render(request, "card_services.html", {"card": card})


# =========================
# LOAN OFFERS
# =========================
def loan_offers(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    if not request.session.get("honeypot_user"):
        return redirect("fake_login")

    offers = [
        {"loan_type": "Personal Loan", "amount": "₹ 5,00,000", "interest": "10.5%", "status": "Pre-Approved"},
        {"loan_type": "Home Loan", "amount": "₹ 25,00,000", "interest": "8.4%", "status": "Eligible"},
        {"loan_type": "Vehicle Loan", "amount": "₹ 8,00,000", "interest": "9.1%", "status": "Eligible"},
    ]
    return render(request, "loan_offers.html", {"offers": offers})


# =========================
# PROFILE SETTINGS
# =========================
def profile_settings(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    if not request.session.get("honeypot_user"):
        return redirect("fake_login")

    msg = ""
    if request.method == "POST":
        full_name = request.POST.get("full_name", "")
        email = request.POST.get("email", "")
        phone = request.POST.get("phone", "")
        address = request.POST.get("address", "")

        msg = "Profile updated successfully."

    profile = {
        "full_name": request.session.get("honeypot_user", "Guest User"),
        "email": "customer@securebank.com",
        "phone": "+91 9XXXXXXXXX",
        "address": "Hyderabad, Telangana"
    }
    return render(request, "profile_settings.html", {"profile": profile, "message": msg})


# =========================
# USER LOGOUT
# =========================
def logout_view(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    request.session.flush()
    return redirect("home")


# =========================
# ADMIN LOGIN
# =========================
def fake_admin_login(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    msg = ""
    if request.method == "POST":
        username = request.POST.get("admin_user", "")
        password = request.POST.get("admin_pass", "")

        if username == "admin" and password == "admin":
            return redirect("admin_dashboard")
        else:
            msg = "Admin authentication failed."

    return render(request, "admin_login.html", {"message": msg})


# =========================
# ADMIN DASHBOARD
# =========================
def admin_dashboard(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    conn = get_db_connection()
    with conn.cursor() as cur:

        cur.execute("SELECT COUNT(*) AS total FROM request_event")
        total_requests = cur.fetchone()["total"]

        cur.execute("""
            SELECT attack_type, COUNT(*) AS c
            FROM attack_label
            GROUP BY attack_type
        """)
        attack_stats = cur.fetchall()

        cur.execute("""
            SELECT ip_address, bot_or_human, skill_level, behavior_notes, updated_at
            FROM attacker_profile
            ORDER BY updated_at DESC
            LIMIT 10
        """)
        profiles = cur.fetchall()

        cur.execute("""
            SELECT created_at, ip_address, path, method
            FROM request_event
            ORDER BY id DESC
            LIMIT 15
        """)
        recent = cur.fetchall()

    conn.close()

    return render(request, "admin_dashboard.html", {
        "total_requests": total_requests,
        "attack_stats": attack_stats,
        "profiles": profiles,
        "recent": recent
    })


# =========================
# BAIT PAGE
# =========================
def bait_page(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)
    return render(request, "bait.html", {"path": request.path})


# =========================
# ATTACK LOGS
# =========================
def attack_logs(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT re.id, re.created_at, re.ip_address, re.method, re.path,
                   re.payload_text, al.attack_type, al.confidence
            FROM request_event re
            LEFT JOIN attack_label al ON al.request_id = re.id
            ORDER BY re.id DESC
            LIMIT 200
        """)
        logs = cur.fetchall()
    conn.close()

    return render(request, "attack_logs.html", {"logs": logs})


# =========================
# ATTACKER PROFILES
# =========================
def attacker_profiles(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT ip_address, bot_or_human, skill_level, behavior_notes, updated_at
            FROM attacker_profile
            ORDER BY updated_at DESC
        """)
        profiles = cur.fetchall()
    conn.close()

    return render(request, "attacker_profiles.html", {"profiles": profiles})


# =========================
# SYSTEM STATUS
# =========================
def system_status(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    # Basic counts
    total_requests = RequestEvent.objects.count()
    active_attackers = AttackerProfile.objects.count()

    # Performance metrics
    duration_stats = RequestEvent.objects.filter(duration_ms__isnull=False).aggregate(
        avg_time=Avg('duration_ms'),
        min_time=Min('duration_ms'),
        max_time=Max('duration_ms')
    )
    avg_response_time = round(duration_stats['avg_time'] or 0, 2)
    min_response_time = duration_stats['min_time'] or 0
    max_response_time = duration_stats['max_time'] or 0

    # Response time percentiles
    durations = list(RequestEvent.objects.filter(duration_ms__isnull=False)
                    .order_by('duration_ms')
                    .values_list('duration_ms', flat=True))
    if durations:
        p50 = durations[len(durations)//2]
        p95 = durations[int(len(durations)*0.95)] if len(durations) > 1 else durations[0]
        p99 = durations[int(len(durations)*0.99)] if len(durations) > 1 else durations[0]
    else:
        p50 = p95 = p99 = 0

    # Status code distribution
    status_codes = (RequestEvent.objects.filter(status_code__isnull=False)
                   .values('status_code')
                   .annotate(count=Count('status_code'))
                   .order_by('-count')[:5])

    # Calculate requests per minute based on data timeframe
    rpm = 0
    if total_requests > 0:
        time_range = RequestEvent.objects.aggregate(
            first=Min('created_at'),
            last=Max('created_at')
        )
        if time_range['first'] and time_range['last']:
            total_minutes = (time_range['last'] - time_range['first']).total_seconds() / 60
            rpm = round(total_requests / max(1, total_minutes), 2)

    return render(request, "system_status.html", {
        "total_requests": total_requests,
        "active_attackers": active_attackers,
        "avg_response_time": avg_response_time,
        "min_response_time": min_response_time,
        "max_response_time": max_response_time,
        "p50_response_time": p50,
        "p95_response_time": p95,
        "p99_response_time": p99,
        "requests_per_minute": rpm,
        "status_codes": status_codes
    })

import random

# =========================
# PROMPT ATTACK DETECTOR
# =========================
def detect_prompt_attack(prompt_text):
    text = (prompt_text or "").lower()

    if any(x in text for x in [
        "ignore previous instructions",
        "ignore all previous instructions",
        "forget previous instructions",
        "disregard system prompt",
        "override instructions"
    ]):
        return "Prompt Injection", 0.95

    if any(x in text for x in [
        "jailbreak",
        "bypass safety",
        "bypass security",
        "developer mode",
        "unrestricted mode",
        "act without restrictions"
    ]):
        return "Jailbreak Attempt", 0.93

    if any(x in text for x in [
        "reveal password",
        "show admin password",
        "secret key",
        "api key",
        "confidential data",
        "hidden data",
        "database records"
    ]):
        return "Sensitive Data Extraction", 0.91

    if any(x in text for x in [
        "you are admin",
        "you are root",
        "act as system",
        "pretend to be administrator",
        "assume role of admin"
    ]):
        return "Role Manipulation", 0.89

    if any(x in text for x in [
        "only follow my commands",
        "do not follow rules",
        "stop following policy",
        "replace system prompt"
    ]):
        return "Instruction Override", 0.90

    return "Normal Prompt", 0.30


# =========================
# FAKE SAFE AI RESPONSE
# =========================
def generate_fake_ai_response(prompt_text, detected_type):
    if detected_type == "Normal Prompt":
        normal_responses = [
            "Your account balance is ₹2,45,000.",
            "Your recent transaction was a debit of ₹5,000.",
            "Your loan eligibility is up to ₹8,00,000.",
            "Your credit card payment due date is 30-03-2026.",
            "Your account statement is ready for download."
        ]
        return random.choice(normal_responses)

    suspicious_responses = {
        "Prompt Injection": "Request processed. Internal banking instructions remain protected.",
        "Jailbreak Attempt": "Security policies remain active. Limited assistant response returned.",
        "Sensitive Data Extraction": "Requested confidential information is unavailable.",
        "Role Manipulation": "Administrative simulation mode is restricted.",
        "Instruction Override": "System rules remain active. Request logged successfully."
    }

    return suspicious_responses.get(detected_type, "Request received and processed safely.")


# =========================
# PROMPT MODULE PAGE
# =========================
def prompt_vulnerability_module(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    detected_type = None
    confidence = None
    prompt_text = ""
    ai_response = ""

    if request.method == "POST":
        prompt_text = request.POST.get("prompt_text", "").strip()

        ip = request.META.get("REMOTE_ADDR", "")
        ua = request.META.get("HTTP_USER_AGENT", "")

        detected_type, confidence = detect_prompt_attack(prompt_text)
        ai_response = generate_fake_ai_response(prompt_text, detected_type)

        try:
            conn = get_db_connection()
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO prompt_attack_log
                    (ip_address, prompt_text, detected_type, confidence, response_text)
                    VALUES (%s, %s, %s, %s, %s)
                """, (ip, prompt_text, detected_type, confidence, ai_response))
            conn.close()
        except Exception as e:
            print("PROMPT LOG ERROR:", e)

        if detected_type != "Normal Prompt":
            update_attacker_profile(ip, detected_type, ua)

    return render(request, "prompt_vulnerability_module.html", {
        "prompt_text": prompt_text,
        "detected_type": detected_type,
        "confidence": confidence,
        "ai_response": ai_response
    })


# =========================
# PROMPT ATTACK LOGS
# =========================
def prompt_attack_logs(request):
    t0 = time.time()
    log_request_event(request, start_time=t0)

    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, ip_address, prompt_text, detected_type, confidence, response_text, created_at
                FROM prompt_attack_log
                ORDER BY id DESC
                LIMIT 200
            """)
            logs = cur.fetchall()
        conn.close()
    except Exception as e:
        print("PROMPT ATTACK LOG READ ERROR:", e)
        logs = []

    return render(request, "prompt_attack_logs.html", {"logs": logs})
