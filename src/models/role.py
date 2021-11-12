from dataclasses import dataclass

from sqlalchemy import DefaultClause, text
from sqlalchemy.dialects.postgresql import UUID

from db.pg import db


@dataclass
class Role(db.Model):
    __tablename__ = 'roles'

    __table_args__ = {'schema': 'app'}

    role_id: str
    role_name: str

    role_id = db.Column(UUID, primary_key=True,
                        server_default=DefaultClause(text("gen_random_uuid()"))
                        )
    role_name = db.Column(db.String, unique=True, nullable=False)
