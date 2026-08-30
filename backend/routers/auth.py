from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from database import get_db
import models, schemas
from auth import hash_password, verify_password, create_access_token, get_current_user, decode_access_token

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

VALID_ROLES = {'admin', 'analyst', 'clinical'}
PRIVILEGED_ROLES = {'admin', 'analyst'}

# In-memory brute-force protection for login.
_LOGIN_ATTEMPTS = {}
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 60


def _requesting_admin(request: Request, db: Session):
    """Best-effort: return the User if the caller presents a valid admin JWT,
    else None. Used so an existing admin can provision privileged accounts
    while anonymous self-registration cannot escalate privileges."""
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
    if user and user.is_active and user.role == 'admin':
        return user
    return None


@router.post("/register", response_model=schemas.UserOut)
def register(user_in: schemas.UserCreate, request: Request, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == user_in.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    requested_role = user_in.role.lower() if user_in.role else 'clinical'
    if requested_role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Choose from: {VALID_ROLES}")

    # SECURITY: privileged roles (admin/analyst) may only be created by an
    # authenticated admin. Anonymous / non-admin self-registration is forced to
    # the least-privileged clinical role to prevent privilege escalation.
    if requested_role in PRIVILEGED_ROLES:
        if _requesting_admin(request, db) is None:
            raise HTTPException(
                status_code=403,
                detail="Privileged accounts (admin/analyst) must be provisioned by an administrator.",
            )
        role = requested_role
    else:
        role = 'clinical'

    clearance_map = {'admin': 5, 'analyst': 3, 'clinical': 4}
    user = models.User(
        full_name=user_in.full_name,
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        role=role,
        clearance_level=clearance_map.get(role, 3)
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
    if not user or not verify_password(user_in.password, user.hashed_password):
        rec = _LOGIN_ATTEMPTS.setdefault(key, {"count": 0, "locked_until": None})
        rec["count"] += 1
        if rec["count"] >= MAX_FAILED_LOGINS:
            rec["locked_until"] = now + timedelta(seconds=LOCKOUT_SECONDS)
            rec["count"] = 0
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Successful login clears the throttle record.
    _LOGIN_ATTEMPTS.pop(key, None)
    user.last_login = datetime.utcnow()
    db.commit()
    # Include role in JWT payload for client-side RBAC
    token = create_access_token(data={"sub": user.email, "role": user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": schemas.UserOut.from_orm(user)
    }

@router.get("/me", response_model=schemas.UserOut)
def me(current_user=Depends(get_current_user)):
    return current_user
