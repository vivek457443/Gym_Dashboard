# notifications.py — Centralised notification system for XYZ Gym
#
# Public API (import these from other modules):
#   send_otp_email(to_email)
#   send_welcome_email(to_email, member_name, membership_type, joining_date, expiry_date, fee)
#   send_welcome_whatsapp(phone_number, member_name, membership_type, joining_date, expiry_date)
#   send_expiry_email(to_email, member_name, membership_type, expiry_date, days_left)
#   send_expiry_whatsapp(phone_number, member_name, expiry_date, days_left)
#   check_membership_expiry_reminders(db)   ← call daily from scheduler
#   get_whatsapp_link(phone_number, message)
#   verify_otp(email, user_submitted_otp)
#   send_email(to_email, subject, message)  ← legacy general-purpose

import logging
import os
import re
import secrets
import smtplib
import ssl
import time
import urllib.parse
from datetime import date, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv optional; env vars can be set another way

try:
    import pywhatkit as kit
except ImportError:
    kit = None

logger = logging.getLogger(__name__)

# =============================================================
# SMTP CREDENTIALS
# Keep real values ONLY in your .env file — not here.
# Fallbacks below are used if env vars are missing.
# =============================================================
_DEFAULT_SMTP_USER     = ""
_DEFAULT_SMTP_PASSWORD = ""   # ← Gmail App Password
_DEFAULT_SMTP_HOST     = "smtp.gmail.com"
_DEFAULT_SMTP_PORT     = 465


# =============================================================
# SMTP HELPERS  (unchanged)
# =============================================================

def _get_smtp_config() -> dict:
    user     = os.getenv("SMTP_USER",     _DEFAULT_SMTP_USER).strip()
    password = os.getenv("SMTP_PASSWORD", _DEFAULT_SMTP_PASSWORD).strip()
    host     = os.getenv("SMTP_HOST",     _DEFAULT_SMTP_HOST).strip()
    port     = int(os.getenv("SMTP_PORT", str(_DEFAULT_SMTP_PORT)))
    sender   = os.getenv("SMTP_FROM",     user).strip()
    return {"user": user, "password": password, "host": host,
            "port": port, "sender": sender}


def _smtp_ready(cfg: dict) -> bool:
    return bool(cfg["user"] and cfg["password"])


def _send_message(cfg: dict, msg: MIMEMultipart) -> None:
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
# IN-MEMORY OTP STORE  (unchanged)
# =============================================================
_otp_store: dict[str, dict] = {}
OTP_EXPIRY_SECONDS = 300
OTP_MAX_ATTEMPTS   = 5


def generate_otp(length: int = 6) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def _store_otp(email: str, otp: str) -> None:
    _otp_store[email] = {
        "otp":        otp,
        "expires_at": time.time() + OTP_EXPIRY_SECONDS,
        "attempts":   0,
    }


def verify_otp(email: str, user_submitted_otp: str) -> dict:
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
# OTP EMAIL  (unchanged)
# =============================================================

def send_otp_email(to_email: str) -> dict:
    cfg = _get_smtp_config()
    if not _smtp_ready(cfg):
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
        print(f"✅ OTP email sent to {to_email}")
        return {"success": True, "message": f"OTP sent to {to_email}"}
    except smtplib.SMTPAuthenticationError:
        _otp_store.pop(to_email, None)
        return {"success": False, "error": "SMTP authentication failed. Check your App Password."}
    except smtplib.SMTPException as e:
        _otp_store.pop(to_email, None)
        return {"success": False, "error": f"SMTP error: {e}"}
    except Exception as e:
        _otp_store.pop(to_email, None)
        return {"success": False, "error": f"Unexpected error: {e}"}


# =============================================================
# WELCOME EMAIL  (unchanged)
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
    Called from /members/add after successful DB commit.
    """
    cfg = _get_smtp_config()
    if not _smtp_ready(cfg):
        print("❌ SMTP not configured — welcome email not sent.")
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
        print(f"✅ Welcome email sent to {to_email}")
        return {"success": True}
    except smtplib.SMTPAuthenticationError:
        print("❌ Welcome email failed: Auth error")
        return {"success": False, "error": "SMTP auth failed"}
    except Exception as e:
        print(f"❌ Welcome email failed: {e}")
        return {"success": False, "error": str(e)}


# =============================================================
# WELCOME WHATSAPP  (NEW)
# =============================================================

def send_welcome_whatsapp(
    phone_number: str,
    member_name: str,
    membership_type: str,
    joining_date,
    expiry_date,
) -> dict:
    """
    Sends a welcome WhatsApp message to a newly registered member.
    Wraps the existing send_whatsapp() so the return type is a consistent dict.

    NOTE: pywhatkit opens a browser tab to send the message. This is a
    library constraint — suitable for desktop/server environments where a
    browser is available. For headless servers, replace kit.sendwhatmsg_instantly
    with a Twilio/WhatsApp Business API call in send_whatsapp().
    """
    message = (
        f"🏋️ *Welcome to XYZ Gym, {member_name}!*\n\n"
        f"You are now a registered member. Here are your details:\n\n"
        f"📋 *Plan:* {membership_type}\n"
        f"📅 *Joined:* {joining_date}\n"
        f"⏳ *Valid Till:* {expiry_date}\n\n"
        f"We're thrilled to have you! Come in and crush those goals 💪\n"
        f"— Team XYZ Gym"
    )
    success = send_whatsapp(phone_number, message)
    if success:
        logger.info("Welcome WhatsApp sent to %s", phone_number)
        return {"success": True}
    return {"success": False, "error": "send_whatsapp returned False — check logs above"}


# =============================================================
# EXPIRY REMINDER EMAIL  (NEW)
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
    Called by check_membership_expiry_reminders() for 7, 3, and 1 day intervals.
    """
    cfg = _get_smtp_config()
    if not _smtp_ready(cfg):
        logger.warning("SMTP not configured — expiry email not sent to %s", to_email)
        return {"success": False, "error": "SMTP not configured."}

    # Urgency styling: red banner for 1 day, orange for 3, yellow for 7
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
        return {"success": False, "error": "SMTP auth failed"}
    except Exception as e:
        logger.exception("Expiry email failed for %s", to_email)
        return {"success": False, "error": str(e)}


# =============================================================
# EXPIRY REMINDER WHATSAPP  (NEW)
# =============================================================

def send_expiry_whatsapp(
    phone_number: str,
    member_name: str,
    expiry_date,
    days_left: int,
) -> dict:
    """
    Sends a membership expiry reminder via WhatsApp.
    Called by check_membership_expiry_reminders() for 7, 3, and 1 day intervals.
    """
    if days_left == 1:
        urgency = "⚠️ *URGENT:* Your membership expires TOMORROW!"
    else:
        urgency = f"📢 Your membership expires in *{days_left} days*."

    message = (
        f"🏋️ *XYZ Gym — Membership Reminder*\n\n"
        f"Hello {member_name},\n\n"
        f"{urgency}\n\n"
        f"📅 *Expiry Date:* {expiry_date}\n\n"
        f"Please renew at the gym to continue without interruption 💪\n"
        f"— Team XYZ Gym"
    )
    success = send_whatsapp(phone_number, message)
    if success:
        logger.info("Expiry WhatsApp sent to %s (%d days left)", phone_number, days_left)
        return {"success": True}
    return {"success": False, "error": "send_whatsapp returned False — check logs above"}


# =============================================================
# LEGACY GENERAL-PURPOSE EMAIL  (unchanged)
# =============================================================

def send_email(to_email: str, subject: str, message: str) -> bool:
    cfg = _get_smtp_config()
    if not _smtp_ready(cfg):
        print("❌ SMTP not configured.")
        return False
    try:
        msg            = MIMEText(message, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"]    = f"XYZ Gym <{cfg['sender']}>"
        msg["To"]      = to_email
        _send_message(cfg, msg)
        print("✅ Email sent successfully")
        return True
    except smtplib.SMTPAuthenticationError:
        print("❌ SMTP authentication failed: use a Gmail App Password.")
    except smtplib.SMTPException as e:
        print(f"❌ SMTP error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
    return False


# =============================================================
# WHATSAPP  (unchanged)
# =============================================================

def _normalise_whatsapp_number(phone_number: str) -> str:
    cleaned = re.sub(r"[^\d+]", "", phone_number.strip())
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    if not cleaned.startswith("+"):
        raise ValueError("WhatsApp number must include country code, e.g. +919876543210")
    if len(re.sub(r"\D", "", cleaned)) < 10:
        raise ValueError("WhatsApp phone number is too short")
    return cleaned


def get_whatsapp_link(phone_number: str, message: str) -> str:
    phone_number = _normalise_whatsapp_number(phone_number)
    return f"https://wa.me/{phone_number.replace('+', '')}?text={urllib.parse.quote(message)}"


def send_whatsapp(phone_number: str, message: str) -> bool:
    try:
        phone_number = _normalise_whatsapp_number(phone_number)
        if kit is None:
            print("❌ pywhatkit not installed. Run: pip install pywhatkit")
            return False
        kit.sendwhatmsg_instantly(phone_number, message, wait_time=20, tab_close=True)
        print("✅ WhatsApp message sent")
        return True
    except Exception as e:
        print(f"❌ WhatsApp failed: {e}")
        return False


# =============================================================
# EXPIRY REMINDER SCHEDULER ENTRY POINT  (NEW)
# =============================================================

# Reminder intervals in days. Adjust here to add/remove intervals globally.
EXPIRY_REMINDER_DAYS: list[int] = [7, 3, 1]


def check_membership_expiry_reminders(db) -> dict:
    """
    Queries all active members whose membership expires in exactly 7, 3, or 1
    day(s) from today, then dispatches both email and WhatsApp reminders.

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
        db: SQLAlchemy Session — caller is responsible for opening/closing it.

    Returns:
        dict with keys:
            "checked"  — number of (member, interval) pairs evaluated
            "sent"     — number of notifications dispatched successfully
            "failed"   — number of notifications that failed
    """
    # Import here (not at module top) to avoid circular imports:
    # notifications.py has no knowledge of models at import time.
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

            # --- Email reminder ---
            if m.email:
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
                            member_label, result.get("error"),
                        )
                except Exception:
                    failed += 1
                    logger.exception("Unexpected error in expiry email for %s", member_label)

            # --- WhatsApp reminder ---
            if m.phone:
                try:
                    result = send_expiry_whatsapp(
                        phone_number=m.phone,
                        member_name=m.name,
                        expiry_date=m.expiry_date,
                        days_left=days_left,
                    )
                    if result.get("success"):
                        sent += 1
                    else:
                        failed += 1
                        logger.warning(
                            "Expiry WhatsApp failed for %s: %s",
                            member_label, result.get("error"),
                        )
                except Exception:
                    failed += 1
                    logger.exception("Unexpected error in expiry WhatsApp for %s", member_label)

    logger.info(
        "Expiry reminder run complete — checked: %d, sent: %d, failed: %d",
        checked, sent, failed,
    )
    return {"checked": checked, "sent": sent, "failed": failed}


# =============================================================
# EMAIL TEST UTILITY  —  python notifications.py  (unchanged)
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
        print("--- Connecting... ---")
        _send_message(cfg, msg)
        print(f"✅ Test email sent to {send_to}!")
        print("👉 Check your inbox (and spam folder)")
    except smtplib.SMTPAuthenticationError as e:
        print(f"\n❌ AUTH FAILED: {e}")
        print("🔧 Go to https://myaccount.google.com/apppasswords and generate a new App Password.")
    except smtplib.SMTPConnectError as e:
        print(f"\n❌ CONNECT FAILED: {e}")
        print("🔧 Try switching port between 465 and 587 in your .env")
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {type(e).__name__}: {e}")

    print("=" * 52)


if __name__ == "__main__":
    run_email_test()