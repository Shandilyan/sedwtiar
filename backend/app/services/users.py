"""User and role management primitives for the forthcoming authentication layer."""

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pwdlib import PasswordHash

from app.models import Role, User
from app.models.enums import AuditOutcome, RoleName
from app.schemas.identity import UserCreate
from app.services.audit_logs import record_audit_log
from app.services.exceptions import ResourceConflictError, ResourceNotFoundError

password_hasher = PasswordHash.recommended()

DEFAULT_ROLE_DESCRIPTIONS = {
    RoleName.ADMIN: "Manages users, roles, and application administration.",
    RoleName.OPERATOR: "Creates operational jobs and records evidence.",
    RoleName.VERIFIER: "Independently verifies evidence and related outcomes.",
    RoleName.AUDITOR: "Reviews audit records and compliance evidence.",
    RoleName.VIEWER: "Reads permitted application data without operational authority.",
}


def ensure_default_roles(db: Session) -> list[Role]:
    """Ensure fixed baseline roles exist; safe to call repeatedly."""
    existing = {role.name: role for role in db.scalars(select(Role))}
    for role_name, description in DEFAULT_ROLE_DESCRIPTIONS.items():
        if role_name not in existing:
            role = Role(name=role_name, description=description)
            db.add(role)
            existing[role_name] = role
    db.flush()
    return [existing[role_name] for role_name in RoleName]


def get_user(db: Session, user_id: str) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise ResourceNotFoundError("User not found")
    return user


def get_user_by_email(db: Session, email: str) -> User | None:
    normalized_email = email.strip().lower()
    return db.scalar(select(User).where(User.email == normalized_email))


def create_user(
    db: Session,
    payload: UserCreate,
    *,
    actor_user_id: str | None = None,
) -> User:
    """Create a user with an Argon2 password hash and baseline role assignments."""
    normalized_email = payload.email.strip().lower()
    if get_user_by_email(db, normalized_email) is not None:
        raise ResourceConflictError("A user with this email already exists")

    roles_by_name = {role.name: role for role in ensure_default_roles(db)}
    requested_role_names = list(dict.fromkeys(payload.roles))
    user = User(
        email=normalized_email,
        display_name=payload.display_name.strip(),
        password_hash=password_hasher.hash(payload.password),
        roles=[roles_by_name[role_name] for role_name in requested_role_names],
    )
    db.add(user)
    db.flush()
    record_audit_log(
        db,
        actor_user_id=actor_user_id,
        action="user.created",
        resource_type="user",
        resource_id=user.id,
        outcome=AuditOutcome.SUCCESS,
        details={"email": user.email, "roles": [role_name.value for role_name in requested_role_names]},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ResourceConflictError("A user with this email already exists") from exc
    db.refresh(user)
    return user


def verify_password(user: User, password: str) -> bool:
    """Verify a password without exposing the stored hash to API callers."""
    return password_hasher.verify(password, user.password_hash)
