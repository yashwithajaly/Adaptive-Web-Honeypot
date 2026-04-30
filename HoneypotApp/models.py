from django.db import models

class AttackSession(models.Model):
    ip_address = models.CharField(max_length=64)
    user_agent = models.TextField()
    start_time = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    request_count = models.IntegerField(default=0)

    class Meta:
        indexes = [
            models.Index(fields=['ip_address', 'user_agent', 'last_seen']),
        ]

class RequestEvent(models.Model):
    session = models.ForeignKey(AttackSession, null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.CharField(max_length=64)
    method = models.CharField(max_length=10)
    path = models.TextField()
    query_string = models.TextField(blank=True)
    headers_text = models.TextField(blank=True)
    payload_text = models.TextField(blank=True)
    user_agent = models.TextField(blank=True)
    referer = models.TextField(blank=True)
    status_code = models.IntegerField(null=True)
    duration_ms = models.IntegerField(null=True)

    class Meta:
        indexes = [
            models.Index(fields=['session']),
            models.Index(fields=['ip_address', 'created_at']),
        ]

class AttackLabel(models.Model):
    request = models.OneToOneField(RequestEvent, on_delete=models.CASCADE)
    attack_type = models.CharField(max_length=50)
    intent_summary = models.TextField(blank=True)
    confidence = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)

class AttackerProfile(models.Model):
    ip_address = models.CharField(max_length=64, unique=True)
    bot_or_human = models.CharField(max_length=20)
    skill_level = models.CharField(max_length=20)
    behavior_notes = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)

class PromptAttackLog(models.Model):
    ip_address = models.CharField(max_length=64)
    prompt_text = models.TextField()
    detected_type = models.CharField(max_length=100)
    confidence = models.FloatField()
    response_text = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
