# notifications.py — Centralised notification system for XYZ Gym
#
# Public API (import these from other modules):
#   send_otp_email(to_email)                                        → dict
#   send_welcome_email(to_email, member_name, membership_type,      → dict
#                      joining_date, expiry_date, fee)
#   send_expiry_email(to_email, member_name, membership_type,       → dict
#                     expiry_date, days_left)
#   check_membership_expiry_reminders(db)   ← call daily from scheduler
#   verify_otp(email, user_submitted_otp)                           → dict
#   send_email(to_email, subject, message)  ← legacy general-purpose → bool

import logging
import os
import secrets
import smtplib
import ssl
import time
from datetime import date, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

# =============================================================
# SMTP CREDENTIALS
# Keep real values ONLY in your .env file — never hard-code here.
# Fallbacks below are intentionally empty; the app will log a
# warning and skip sending rather than fail loudly.
# =============================================================
_DEFAULT_SMTP_USER     = ""
_DEFAULT_SMTP_PASSWORD = ""   # ← Gmail App Password
_DEFAULT_SMTP_HOST     = "smtp.gmail.com"
_DEFAULT_SMTP_PORT     = 465


# =============================================================
# SMTP HELPERS
# =============================================================

def _get_smtp_config() -> dict:
    user     = os.getenv("SMTP_USER",     _DEFAULT_SMTP_USER).strip()
    password = os.getenv("SMTP_PASSWORD", _DEFAULT_SMTP_PASSWORD).strip()
    host     = os.getenv("SMTP_HOST",     _DEFAULT_SMTP_HOST).strip()
    port     = int(os.getenv("SMTP_PORT", str(_DEFAULT_SMTP_PORT)))
    sender   = os.getenv("SMTP_FROM",     user).strip()
    return {
        "user": user,
        "password": password,
        "host": host,
        "port": port,
        "sender": sender,
    }


def _smtp_ready(cfg: dict) -> bool:
    return bool(cfg["user"] and cfg["password"])


def _send_message(cfg: dict, msg: MIMEMultipart) -> None:
    """
    Dispatches a pre-built MIME message via SMTP.
    Uses SSL on port 465, STARTTLS on all other ports.
    """
    context = ssl.create_default_context()
    if cfg["port"] == 465:
        with smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=context, timeout=30) as srv:
            srv.login(cfg["user"], cfg["password"])
            srv.send_message(msg)
    else:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=30) as srv:
            srv.ehlo()
            srv.starttls(context=context)
            srv.ehlo()
            srv.login(cfg["user"], cfg["password"])
            srv.send_message(msg)


# =============================================================
# IN-MEMORY OTP STORE
# =============================================================
_otp_store: dict[str, dict] = {}
OTP_EXPIRY_SECONDS = 300   # 5 minutes
OTP_MAX_ATTEMPTS   = 5


def generate_otp(length: int = 6) -> str:
    """Returns a cryptographically random numeric OTP string."""
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def _store_otp(email: str, otp: str) -> None:
    _otp_store[email] = {
        "otp":        otp,
        "expires_at": time.time() + OTP_EXPIRY_SECONDS,
        "attempts":   0,
    }


def verify_otp(email: str, user_submitted_otp: str) -> dict:
    """
    Validates a submitted OTP against the in-memory store.

    Returns:
        {"success": True} on success, or
        {"success": False, "error": "<reason>"} on failure.
    """
    record = _otp_store.get(email)
    if not record:
        return {"success": False, "error": "No OTP found for this email. Please request a new one."}
    if time.time() > record["expires_at"]:
        _otp_store.pop(email, None)
        return {"success": False, "error": "OTP has expired. Please request a new one."}
    if record["attempts"] >= OTP_MAX_ATTEMPTS:
        _otp_store.pop(email, None)
        return {"success": False, "error": "Too many failed attempts. Please request a new OTP."}

    record["attempts"] += 1
    if not secrets.compare_digest(record["otp"], user_submitted_otp.strip()):
        remaining = OTP_MAX_ATTEMPTS - record["attempts"]
        return {"success": False, "error": f"Invalid OTP. {remaining} attempt(s) remaining."}

    _otp_store.pop(email, None)
    return {"success": True}


# =============================================================
# OTP EMAIL
# =============================================================

def send_otp_email(to_email: str) -> dict:
    """
    Generates a fresh OTP, stores it, and e-mails it to *to_email*.

    Returns:
        {"success": True, "message": "..."} or {"success": False, "error": "..."}
    """
    cfg = _get_smtp_config()
    if not _smtp_ready(cfg):
        logger.error("SMTP not configured — OTP email not sent to %s", to_email)
        return {"success": False, "error": "SMTP not configured. Set SMTP_USER and SMTP_PASSWORD in .env"}

    otp = generate_otp()
    _store_otp(to_email, otp)

    plain = (
        f"Welcome to XYZ Gym! 🏋️\n\n"
        f"Your one-time verification code is: {otp}\n\n"
        f"This code expires in {OTP_EXPIRY_SECONDS // 60} minutes.\n"
        "Do not share this code with anyone.\n\n"
        "— Team XYZ Gym 💪"
    )

    html = f"""
    <html>
      <body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:40px;">
        <div style="max-width:480px;margin:auto;background:#fff;border-radius:8px;
                    padding:32px;box-shadow:0 2px 8px rgba(0,0,0,.1);">
          <h2 style="margin-top:0;color:#4f46e5;">🏋️ XYZ Gym</h2>
          <p style="color:#444;">Hello! Use the code below to log in to your Gym Admin Dashboard:</p>
          <div style="font-size:36px;font-weight:bold;letter-spacing:8px;
                      text-align:center;padding:20px;background:#f0f4ff;
                      border-radius:6px;color:#1a1a2e;margin:20px 0;">
            {otp}
          </div>
          <p style="color:#666;font-size:13px;">
            ⏰ Expires in <strong>{OTP_EXPIRY_SECONDS // 60} minutes</strong>.<br>
            🔒 Never share this code with anyone.<br>
            If you did not request this, please ignore this email.
          </p>
          <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
          <p style="color:#aaa;font-size:12px;text-align:center;">© XYZ Gym Management System</p>
        </div>
      </body>
    </html>
    """

    try:
        msg            = MIMEMultipart("alternative")
        msg["Subject"] = "🏋️ XYZ Gym — Your Login Verification Code"
        msg["From"]    = f"XYZ Gym <{cfg['sender']}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(plain, "plain", "utf-8"))
        msg.attach(MIMEText(html,  "html",  "utf-8"))
        _send_message(cfg, msg)
        logger.info("OTP email sent to %s", to_email)
        return {"success": True, "message": f"OTP sent to {to_email}"}
    except smtplib.SMTPAuthenticationError:
        _otp_store.pop(to_email, None)
        logger.error("OTP email auth failure for %s", to_email)
        return {"success": False, "error": "SMTP authentication failed. Check your App Password."}
    except smtplib.SMTPException as exc:
        _otp_store.pop(to_email, None)
        logger.error("OTP SMTP error for %s: %s", to_email, exc)
        return {"success": False, "error": f"SMTP error: {exc}"}
    except Exception as exc:
        _otp_store.pop(to_email, None)
        logger.exception("Unexpected error sending OTP to %s", to_email)
        return {"success": False, "error": f"Unexpected error: {exc}"}


# =============================================================
# WELCOME EMAIL
# =============================================================

def send_welcome_email(
    to_email: str,
    member_name: str,
    membership_type: str,
    joining_date,
    expiry_date,
    fee: float,
) -> dict:
    """
    Sends a welcome registration email to a newly added gym member.
    Call this from /members/add after a successful DB commit.

    Returns:
        {"success": True} or {"success": False, "error": "..."}
    """
    cfg = _get_smtp_config()
    if not _smtp_ready(cfg):
        logger.warning("SMTP not configured — welcome email not sent to %s", to_email)
        return {"success": False, "error": "SMTP not configured."}

    plain = (
        f"Dear {member_name},\n\n"
        f"Welcome to XYZ Gym! 🏋️\n\n"
        f"You have been successfully registered as a member.\n\n"
        f"📋 Membership Details:\n"
        f"   • Plan        : {membership_type}\n"
        f"   • Joining Date: {joining_date}\n"
        f"   • Valid Until : {expiry_date}\n"
        f"   • Fee Paid    : ₹{fee:.0f}\n\n"
        f"We're excited to have you with us. Let's crush those goals! 💪\n\n"
        f"— Team XYZ Gym\n"
        f"📍 XYZ Gym, New Delhi, India\n"
        f"📞 +91-XXXXXXXXXX"
    )

    html = f"""
    <html>
      <body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:40px;margin:0;">
        <div style="max-width:520px;margin:auto;background:#fff;border-radius:10px;
                    box-shadow:0 2px 12px rgba(0,0,0,0.1);overflow:hidden;">

          <div style="background:linear-gradient(135deg,#4f46e5,#7c3aed);padding:30px;text-align:center;">
            <h1 style="color:#fff;margin:0;font-size:28px;">🏋️ XYZ Gym</h1>
            <p style="color:#c7d2fe;margin:6px 0 0;font-size:14px;">Welcome to the Family!</p>
          </div>

          <div style="padding:32px;">
            <h2 style="color:#111;margin-top:0;">Hello, {member_name}! 👋</h2>
            <p style="color:#444;line-height:1.6;">
              You have been <strong>successfully registered</strong> at
              <strong>XYZ Gym</strong>. We are thrilled to have you on board!
            </p>

            <div style="background:#f0f4ff;border-radius:8px;padding:20px;margin:20px 0;">
              <h3 style="margin:0 0 12px;color:#4f46e5;">📋 Your Membership Details</h3>
              <table style="width:100%;border-collapse:collapse;font-size:14px;color:#333;">
                <tr style="border-bottom:1px solid #e0e7ff;">
                  <td style="padding:8px 0;color:#666;">Plan</td>
                  <td style="padding:8px 0;font-weight:bold;">{membership_type}</td>
                </tr>
                <tr style="border-bottom:1px solid #e0e7ff;">
                  <td style="padding:8px 0;color:#666;">Joining Date</td>
                  <td style="padding:8px 0;font-weight:bold;">{joining_date}</td>
                </tr>
                <tr style="border-bottom:1px solid #e0e7ff;">
                  <td style="padding:8px 0;color:#666;">Valid Until</td>
                  <td style="padding:8px 0;font-weight:bold;color:#dc2626;">{expiry_date}</td>
                </tr>
                <tr>
                  <td style="padding:8px 0;color:#666;">Fee Paid</td>
                  <td style="padding:8px 0;font-weight:bold;color:#16a34a;">₹{fee:.0f}</td>
                </tr>
              </table>
            </div>

            <p style="color:#444;line-height:1.6;">
              Visit us daily and make the most of your membership.
              Our trainers are here to help you every step of the way! 💪
            </p>

            <div style="text-align:center;margin:24px 0;">
              <span style="background:#4f46e5;color:#fff;padding:12px 28px;
                           border-radius:6px;font-weight:bold;font-size:15px;">
                Let's Get Started! 🚀
              </span>
            </div>
          </div>

          <div style="background:#f9fafb;padding:20px;text-align:center;border-top:1px solid #e5e7eb;">
            <p style="margin:0;color:#9ca3af;font-size:12px;">
              © XYZ Gym Management System &nbsp;|&nbsp; 📍 New Delhi, India &nbsp;|&nbsp; 📞 +91-XXXXXXXXXX
            </p>
            <p style="margin:6px 0 0;color:#d1d5db;font-size:11px;">
              This is an automated message. Please do not reply.
            </p>
          </div>

        </div>
      </body>
    </html>
    """

    try:
        msg            = MIMEMultipart("alternative")
        msg["Subject"] = f"🏋️ Welcome to XYZ Gym, {member_name}!"
        msg["From"]    = f"XYZ Gym <{cfg['sender']}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(plain, "plain", "utf-8"))
        msg.attach(MIMEText(html,  "html",  "utf-8"))
        _send_message(cfg, msg)
        logger.info("Welcome email sent to %s", to_email)
        return {"success": True}
    except smtplib.SMTPAuthenticationError:
        logger.error("Welcome email auth failure for %s", to_email)
        return {"success": False, "error": "SMTP authentication failed."}
    except Exception as exc:
        logger.exception("Welcome email failed for %s", to_email)
        return {"success": False, "error": str(exc)}


# =============================================================
# EXPIRY REMINDER EMAIL
# =============================================================

def send_expiry_email(
    to_email: str,
    member_name: str,
    membership_type: str,
    expiry_date,
    days_left: int,
) -> dict:
    """
    Sends a membership expiry reminder email.
    Called by check_membership_expiry_reminders() for 7, 3, and 1-day intervals.

    Returns:
        {"success": True} or {"success": False, "error": "..."}
    """
    cfg = _get_smtp_config()
    if not _smtp_ready(cfg):
        logger.warning("SMTP not configured — expiry email not sent to %s", to_email)
        return {"success": False, "error": "SMTP not configured."}

    # Urgency styling: red banner for 1 day, orange for ≤3, yellow for 7
    if days_left == 1:
        banner_color = "linear-gradient(135deg,#dc2626,#b91c1c)"
        urgency_line = "⚠️ Your membership expires <strong>TOMORROW</strong>!"
    elif days_left <= 3:
        banner_color = "linear-gradient(135deg,#ea580c,#c2410c)"
        urgency_line = f"⚠️ Your membership expires in <strong>{days_left} days</strong>."
    else:
        banner_color = "linear-gradient(135deg,#ca8a04,#a16207)"
        urgency_line = f"📢 Your membership expires in <strong>{days_left} days</strong>."

    plain = (
        f"Dear {member_name},\n\n"
        f"This is a reminder that your XYZ Gym membership is expiring soon.\n\n"
        f"📋 Membership Details:\n"
        f"   • Plan       : {membership_type}\n"
        f"   • Expiry Date: {expiry_date}\n"
        f"   • Days Left  : {days_left}\n\n"
        f"Please renew your membership to continue enjoying uninterrupted access.\n\n"
        f"— Team XYZ Gym\n"
        f"📍 XYZ Gym, New Delhi, India\n"
        f"📞 +91-XXXXXXXXXX"
    )

    html = f"""
    <html>
      <body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:40px;margin:0;">
        <div style="max-width:520px;margin:auto;background:#fff;border-radius:10px;
                    box-shadow:0 2px 12px rgba(0,0,0,0.1);overflow:hidden;">

          <div style="background:{banner_color};padding:30px;text-align:center;">
            <h1 style="color:#fff;margin:0;font-size:26px;">🏋️ XYZ Gym</h1>
            <p style="color:#fef3c7;margin:6px 0 0;font-size:14px;">Membership Expiry Reminder</p>
          </div>

          <div style="padding:32px;">
            <h2 style="color:#111;margin-top:0;">Hello, {member_name}! 👋</h2>
            <p style="color:#444;line-height:1.6;">{urgency_line}</p>

            <div style="background:#fff7ed;border-left:4px solid #ea580c;
                        border-radius:4px;padding:16px 20px;margin:20px 0;">
              <h3 style="margin:0 0 10px;color:#c2410c;">📋 Membership Details</h3>
              <table style="width:100%;border-collapse:collapse;font-size:14px;color:#333;">
                <tr style="border-bottom:1px solid #fed7aa;">
                  <td style="padding:8px 0;color:#666;">Plan</td>
                  <td style="padding:8px 0;font-weight:bold;">{membership_type}</td>
                </tr>
                <tr style="border-bottom:1px solid #fed7aa;">
                  <td style="padding:8px 0;color:#666;">Expiry Date</td>
                  <td style="padding:8px 0;font-weight:bold;color:#dc2626;">{expiry_date}</td>
                </tr>
                <tr>
                  <td style="padding:8px 0;color:#666;">Days Remaining</td>
                  <td style="padding:8px 0;font-weight:bold;color:#dc2626;">{days_left} day(s)</td>
                </tr>
              </table>
            </div>

            <p style="color:#444;line-height:1.6;">
              Renew today to keep your momentum going.
              Visit the gym or contact us to renew your plan. 💪
            </p>
          </div>

          <div style="background:#f9fafb;padding:20px;text-align:center;border-top:1px solid #e5e7eb;">
            <p style="margin:0;color:#9ca3af;font-size:12px;">
              © XYZ Gym Management System &nbsp;|&nbsp; 📍 New Delhi, India &nbsp;|&nbsp; 📞 +91-XXXXXXXXXX
            </p>
            <p style="margin:6px 0 0;color:#d1d5db;font-size:11px;">
              This is an automated reminder. Please do not reply.
            </p>
          </div>

        </div>
      </body>
    </html>
    """

    try:
        msg            = MIMEMultipart("alternative")
        msg["Subject"] = f"⏳ XYZ Gym — Your membership expires in {days_left} day(s)"
        msg["From"]    = f"XYZ Gym <{cfg['sender']}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(plain, "plain", "utf-8"))
        msg.attach(MIMEText(html,  "html",  "utf-8"))
        _send_message(cfg, msg)
        logger.info("Expiry reminder email sent to %s (%d days left)", to_email, days_left)
        return {"success": True}
    except smtplib.SMTPAuthenticationError:
        logger.error("Expiry email auth failure for %s", to_email)
        return {"success": False, "error": "SMTP authentication failed."}
    except Exception as exc:
        logger.exception("Expiry email failed for %s", to_email)
        return {"success": False, "error": str(exc)}


# =============================================================
# LEGACY GENERAL-PURPOSE EMAIL
# =============================================================

def send_email(to_email: str, subject: str, message: str) -> bool:
    """
    Sends a plain-text email. Kept for backward compatibility.

    Returns True on success, False on any failure.
    """
    cfg = _get_smtp_config()
    if not _smtp_ready(cfg):
        logger.error("SMTP not configured — send_email aborted.")
        return False
    try:
        msg            = MIMEText(message, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"]    = f"XYZ Gym <{cfg['sender']}>"
        msg["To"]      = to_email
        _send_message(cfg, msg)
        logger.info("Generic email sent to %s", to_email)
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error("send_email: SMTP authentication failed.")
    except smtplib.SMTPException as exc:
        logger.error("send_email: SMTP error: %s", exc)
    except Exception as exc:
        logger.exception("send_email: unexpected error sending to %s", to_email)
    return False


# =============================================================
# EXPIRY REMINDER SCHEDULER ENTRY POINT
# =============================================================

# Reminder intervals in days — adjust here to change globally.
EXPIRY_REMINDER_DAYS: list[int] = [7, 3, 1]


def check_membership_expiry_reminders(db) -> dict:
    """
    Queries all active members whose membership expires in exactly 7, 3, or 1
    day(s) from today and dispatches email reminders.

    Designed to be called once daily by any scheduler:
        APScheduler, Celery beat, cron, Render Cron Job, Railway Cron, etc.

    Example APScheduler wiring (in main.py or a scheduler module):

        from apscheduler.schedulers.background import BackgroundScheduler
        from database import SessionLocal
        from notifications import check_membership_expiry_reminders

        def run_expiry_check():
            db = SessionLocal()
            try:
                check_membership_expiry_reminders(db)
            finally:
                db.close()

        scheduler = BackgroundScheduler()
        scheduler.add_job(run_expiry_check, "cron", hour=9, minute=0)
        scheduler.start()

    Args:
        db: SQLAlchemy Session — the caller is responsible for open/close.

    Returns:
        {
            "checked": <int>,   # (member, interval) pairs evaluated
            "sent":    <int>,   # notifications dispatched successfully
            "failed":  <int>,   # notifications that failed
        }
    """
    # Deferred import to avoid circular-import issues at module load time.
    from models import Member  # noqa: PLC0415

    today   = date.today()
    checked = sent = failed = 0

    for days_left in EXPIRY_REMINDER_DAYS:
        target_date = today + timedelta(days=days_left)
        members = (
            db.query(Member)
            .filter(Member.expiry_date == target_date, Member.active == True)  # noqa: E712
            .all()
        )

        for m in members:
            checked += 1
            member_label = f"{m.name} (id={m.id}, days_left={days_left})"

            if not m.email:
                logger.debug("Skipping expiry reminder for %s — no email on record", member_label)
                continue

            try:
                result = send_expiry_email(
                    to_email=m.email,
                    member_name=m.name,
                    membership_type=m.membership_type,
                    expiry_date=m.expiry_date,
                    days_left=days_left,
                )
                if result.get("success"):
                    sent += 1
                else:
                    failed += 1
                    logger.warning(
                        "Expiry email failed for %s: %s",
                        member_label,
                        result.get("error"),
                    )
            except Exception:
                failed += 1
                logger.exception("Unexpected error in expiry email for %s", member_label)

    logger.info(
        "Expiry reminder run complete — checked: %d, sent: %d, failed: %d",
        checked, sent, failed,
    )
    return {"checked": checked, "sent": sent, "failed": failed}


# =============================================================
# EMAIL TEST UTILITY  —  python notifications.py
# =============================================================

def run_email_test(send_to: str | None = None) -> None:
    cfg     = _get_smtp_config()
    send_to = send_to or cfg["sender"]

    print("=" * 52)
    print("   XYZ GYM — EMAIL DEBUG TEST")
    print("=" * 52)
    print(f"  SMTP Host    : {cfg['host']}")
    print(f"  SMTP Port    : {cfg['port']}")
    print(f"  SMTP User    : {cfg['user']}")
    print(f"  App Password : {'*' * len(cfg['password'])} (len={len(cfg['password'])})")
    print(f"  Sending to   : {send_to}")
    print()

    if not _smtp_ready(cfg):
        print("❌ SMTP not configured — set SMTP_USER and SMTP_PASSWORD in .env")
        return

    try:
        msg            = MIMEMultipart("alternative")
        msg["Subject"] = "✅ XYZ Gym — Email System Test Successful"
        msg["From"]    = f"XYZ Gym <{cfg['sender']}>"
        msg["To"]      = send_to
        msg.attach(MIMEText("Test email from XYZ Gym. Working!", "plain", "utf-8"))
        print("--- Connecting… ---")
        _send_message(cfg, msg)
        print(f"✅ Test email sent to {send_to}!")
        print("👉 Check your inbox (and spam folder)")
    except smtplib.SMTPAuthenticationError as exc:
        print(f"\n❌ AUTH FAILED: {exc}")
        print("🔧 Go to https://myaccount.google.com/apppasswords and generate a new App Password.")
    except smtplib.SMTPConnectError as exc:
        print(f"\n❌ CONNECT FAILED: {exc}")
        print("🔧 Try switching port between 465 and 587 in your .env")
    except Exception as exc:
        print(f"\n❌ UNEXPECTED ERROR: {type(exc).__name__}: {exc}")

    print("=" * 52)


if __name__ == "__main__":
    run_email_test()
