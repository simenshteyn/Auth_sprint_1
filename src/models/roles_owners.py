from dataclasses import dataclass

from sqlalchemy import DefaultClause, text
from sqlalchemy.dialects.postgresql import UUID

from db.pg import db


@dataclass
class RoleOwner(db.Model):
    __tablename__ = 'roles_owners'

    __table_args__ = {'schema': 'app'}

    role_owner_id: str = db.Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=DefaultClause(text("gen_random_uuid()"))
    )
    owner_id: str = db.Column(
        UUID(as_uuid=True),
        db.ForeignKey('app.users.user_id'),
        nullable=False
    )
    role_id: str = db.Column(
        UUID(as_uuid=True),
        db.ForeignKey('app.roles.role_id'),
        nullable=False
    )
