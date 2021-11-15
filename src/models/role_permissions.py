from dataclasses import dataclass

from sqlalchemy import DefaultClause, text
from sqlalchemy.dialects.postgresql import UUID

from db.pg import db


@dataclass
class RolePermission(db.Model):
    __tablename__ = 'role_permissions'

    __table_args__ = {'schema': 'app'}

    role_permission_id: str = db.Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=DefaultClause(text("gen_random_uuid()"))
    )
    role_id: str = db.Column(UUID(as_uuid=True),
                             db.ForeignKey('app.roles.role_id'),
                             nullable=False)
    permission_id: str = db.Column(UUID(as_uuid=True),
                                   db.ForeignKey('app.permissions.permission_id'),
                                   nullable=False)
