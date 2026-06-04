# routes/members.py - CRUD for members, with image upload
import logging
import os
import uuid
from datetime import date, timedelta

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from auth import login_required
from database import get_db
from models import Member, Payment, Trainer
from notifications import send_welcome_email

router = APIRouter(prefix="/members")
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger(__name__)

PLAN_DAYS = {"Monthly": 30, "Quarterly": 90, "Yearly": 365}
UPLOAD_DIR = "static/uploads"


def _save_image(file: UploadFile | None) -> str | None:
    if not file or not file.filename:
        return None
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in (".jpg", ".jpeg", ".png", ".webp"):
        return None
    name = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(UPLOAD_DIR, name)
    with open(path, "wb") as f:
        f.write(file.file.read())
    return name


@router.get("")
def list_members(request: Request,
                 user: str = Depends(login_required),
                 db: Session = Depends(get_db),
                 q: str = "", page: int = 1):
    per_page = 10
    query = db.query(Member)
    if q:
        like = f"%{q}%"
        query = query.filter(
            (Member.name.ilike(like)) | (Member.phone.ilike(like)) |
            (Member.email.ilike(like)))
    total = query.count()
    members = query.order_by(Member.id.desc()).offset(
        (page - 1) * per_page).limit(per_page).all()
    pages = max(1, (total + per_page - 1) // per_page)
    trainers = db.query(Trainer).all()
    return templates.TemplateResponse("members.html", {
        "request": request, "user": user, "members": members,
        "trainers": trainers, "q": q, "page": page, "pages": pages,
        "today": date.today(), "active_page": "members",
    })


@router.post("/add")
def add_member(request: Request,
               user: str = Depends(login_required),
               db: Session = Depends(get_db),
               name: str = Form(...),
               phone: str = Form(""), email: str = Form(""),
               age: int = Form(0), gender: str = Form("Male"),
               membership_type: str = Form("Monthly"),
               fee: float = Form(0.0),
               payment_status: str = Form("Paid"),
               trainer_id: int = Form(0),
               image: UploadFile = File(None)):
    joining = date.today()
    expiry = joining + timedelta(days=PLAN_DAYS.get(membership_type, 30))
    m = Member(
        name=name, phone=phone, email=email, age=age, gender=gender,
        joining_date=joining, membership_type=membership_type,
        expiry_date=expiry, fee=fee, payment_status=payment_status,
        trainer_id=trainer_id or None,
        image=_save_image(image), active=True,
    )
    db.add(m)
    db.commit()
    db.refresh(m)

    if payment_status == "Paid" and fee > 0:
        db.add(Payment(member_id=m.id, amount=fee, plan=membership_type))
        db.commit()

    # ------------------------------------------------------------------ #
    # Welcome email — failure is logged but must never abort registration
    # ------------------------------------------------------------------ #
    if m.email:
        try:
            result = send_welcome_email(
                to_email=m.email,
                member_name=m.name,
                membership_type=m.membership_type,
                joining_date=m.joining_date,
                expiry_date=m.expiry_date,
                fee=m.fee,
            )
            if not result.get("success"):
                logger.warning(
                    "Welcome email not sent for member %s (id=%s): %s",
                    m.name, m.id, result.get("error", "unknown error"),
                )
        except Exception:
            logger.exception(
                "Unexpected error sending welcome email for member %s (id=%s)",
                m.name, m.id,
            )
    # ------------------------------------------------------------------ #

    return RedirectResponse("/members", status_code=303)


@router.post("/edit/{mid}")
def edit_member(mid: int, request: Request,
                user: str = Depends(login_required),
                db: Session = Depends(get_db),
                name: str = Form(...),
                phone: str = Form(""), email: str = Form(""),
                age: int = Form(0), gender: str = Form("Male"),
                membership_type: str = Form("Monthly"),
                fee: float = Form(0.0),
                payment_status: str = Form("Paid"),
                trainer_id: int = Form(0),
                image: UploadFile = File(None)):
    m = db.query(Member).get(mid)
    if not m:
        return RedirectResponse("/members", status_code=303)
    m.name = name; m.phone = phone; m.email = email
    m.age = age; m.gender = gender
    if m.membership_type != membership_type:
        m.expiry_date = (m.joining_date or date.today()) + timedelta(
            days=PLAN_DAYS.get(membership_type, 30))
    m.membership_type = membership_type
    m.fee = fee; m.payment_status = payment_status
    m.trainer_id = trainer_id or None
    new_img = _save_image(image)
    if new_img:
        m.image = new_img
    db.commit()
    return RedirectResponse("/members", status_code=303)


@router.get("/delete/{mid}")
def delete_member(mid: int,
                  user: str = Depends(login_required),
                  db: Session = Depends(get_db)):
    m = db.query(Member).get(mid)
    if m:
        db.delete(m); db.commit()
    return RedirectResponse("/members", status_code=303)
