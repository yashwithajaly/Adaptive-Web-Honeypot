from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path("", views.home, name="home"),
    path("login/", views.fake_login, name="fake_login"),
    path("dashboard/", views.bank_dashboard, name="bank_dashboard"),
    path("account-summary/", views.account_summary, name="account_summary"),
    path("transfer-money/", views.transfer_money, name="transfer_money"),
    path("transaction-history/", views.transaction_history, name="transaction_history"),
    path("beneficiary/", views.beneficiary_page, name="beneficiary_page"),
    path("card-services/", views.card_services, name="card_services"),
    path("loan-offers/", views.loan_offers, name="loan_offers"),
    path("profile-settings/", views.profile_settings, name="profile_settings"),
    path("logout/", views.logout_view, name="logout_view"),

    path("admin-login/", views.fake_admin_login, name="fake_admin_login"),
    path("admin-dashboard/", views.admin_dashboard, name="admin_dashboard"),
    path("attack-logs/", views.attack_logs, name="attack_logs"),
    path("attacker-profiles/", views.attacker_profiles, name="attacker_profiles"),
    path("system-status/", views.system_status, name="system_status"),

    path("wp-login.php", views.bait_page, name="wp_login_bait"),
    path("phpmyadmin/", views.bait_page, name="phpmyadmin_bait"),
    path(".env", views.bait_page, name="env_bait"),
    path("backup.zip", views.bait_page, name="backup_bait"),

    path("prompt-vulnerability-module/", views.prompt_vulnerability_module, name="prompt_vulnerability_module"),
    path("prompt-attack-logs/", views.prompt_attack_logs, name="prompt_attack_logs"),
]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
