from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from database import get_db
import models, schemas
from auth import hash_password, verify_password, create_access_token, get_current_user, decode_access_token
from hospital_audit import note_failed_login, note_successful_login
from roles import ALL_ROLES, CLEARANCE, can_assign

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

VALID_ROLES = ALL_ROLES

# In-memory brute-force protection for login.
_LOGIN_ATTEMPTS = {}
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 60


def _requesting_provisioner(request: Request, db: Session):
    """Return the caller when they are an ICDS admin or hospital admin."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    try:
        payload = decode_access_token(token)
        email = payload.get("sub") if payload else None
    except Exception:
        return None
    if not email:
        return None
    user = db.query(models.User).filter(models.User.email == email).first()
    if user and user.is_active and user.role in {"admin", "hospital_admin"}:
        return user
    return None


@router.post("/register", response_model=schemas.UserOut)
def register(user_in: schemas.UserCreate, request: Request, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == user_in.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    requested_role = user_in.role.lower() if user_in.role else 'clinical'
    if requested_role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Choose from: {sorted(VALID_ROLES)}")

    # Public registration can only create a clinical account.
    # Every other role is assigned by an ICDS admin or hospital admin.
    if requested_role == "clinical":
        role = "clinical"
    else:
        creator = _requesting_provisioner(request, db)
        if creator is None or not can_assign(creator.role, requested_role):
            raise HTTPException(
                status_code=403,
                detail="That role must be assigned by an ICDS admin or hospital admin.",
            )
        role = requested_role

    user = models.User(
        full_name=user_in.full_name,
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        role=role,
        clearance_level=CLEARANCE.get(role, 1)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@router.post("/login", response_model=schemas.Token)
def login(user_in: schemas.UserLogin, request: Request, db: Session = Depends(get_db)):
    # SECURITY: in-memory brute-force throttle. After MAX_FAILED failed attempts
    # for an email, further attempts are rejected for LOCKOUT_SECONDS.
    key = (user_in.email or "").lower()
    now = datetime.utcnow()
    record = _LOGIN_ATTEMPTS.get(key)
    if record and record["locked_until"] and record["locked_until"] > now:
        remaining = int((record["locked_until"] - now).total_seconds())
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts. Try again in {remaining}s.",
        )

    user = db.query(models.User).filter(models.User.email == user_in.email).first()
    if user is None:
        user = (
            db.query(models.User)
            .filter(models.User.email.ilike(user_in.email))
            .first()
        )
    password_ok = bool(user) and verify_password(user_in.password, user.hashed_password)
    if not password_ok:
        rec = _LOGIN_ATTEMPTS.setdefault(key, {"count": 0, "locked_until": None})
        rec["count"] += 1
        if rec["count"] >= MAX_FAILED_LOGINS:
            rec["locked_until"] = now + timedelta(seconds=LOCKOUT_SECONDS)
            rec["count"] = 0
        try:
            note_failed_login(db, request, user_in.email, user)
        except Exception:
            db.rollback()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Successful login clears the throttle record.
    _LOGIN_ATTEMPTS.pop(key, None)
    user.last_login = datetime.utcnow()
    try:
        note_successful_login(db, request, user)
    except Exception:
        db.rollback()
        user.last_login = datetime.utcnow()
        db.commit()
    # Include role in JWT payload for client-side RBAC
    token = create_access_token(data={"sub": user.email, "role": user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": schemas.UserOut.model_validate(user)
    }

@router.get("/me", response_model=schemas.UserOut)
def me(current_user=Depends(get_current_user)):
    return current_user
