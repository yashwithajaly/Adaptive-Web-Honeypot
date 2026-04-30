import json

def profile_attacker(stats):
    req_count = stats["request_count"]
    duration = stats["duration_sec"] or 1
    distinct_paths = stats["distinct_paths"]
    attacks = stats["attack_counts"]

    rpm = (req_count / duration) * 60.0

    # BOT detection
    if rpm > 40 and distinct_paths <= 3:
        bot = "Bot"
    else:
        bot = "Human"

    # Skill estimation
    sqli = attacks.get("SQL Injection", 0)
    xss = attacks.get("XSS", 0)
    brute = attacks.get("Brute Force", 0)

    if sqli + xss >= 1:
        skill = "High"
    elif brute >= 5:
        skill = "Low"
    else:
        skill = "Medium"

    notes = f"req={req_count}, rpm={rpm:.1f}, paths={distinct_paths}, attacks={json.dumps(attacks)}"

    return bot, skill, notes
