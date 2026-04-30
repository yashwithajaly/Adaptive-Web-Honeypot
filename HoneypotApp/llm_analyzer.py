import os
import json
from openai import OpenAI

client = OpenAI(api_key="sk-xxxx")

def analyze_with_llm(payload_text, path, method):
    prompt = f"""
You are a cybersecurity analyst.

Analyze this HTTP request:

Path: {path}
Method: {method}
Payload: {payload_text}

1. What type of attack is this? (SQL Injection, XSS, Command Injection, Brute Force, Recon, Unknown)
2. What is the attacker trying to do?
3. Confidence from 0 to 1.

Respond strictly in JSON:
{{
  "attack_type": "...",
  "intent_summary": "...",
  "confidence": 0.0
}}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2
    )

    try:
        data = json.loads(response.choices[0].message.content)
        return data["attack_type"], data["intent_summary"], float(data["confidence"])
    except:
        return "Unknown", "LLM parsing error", 0.0
