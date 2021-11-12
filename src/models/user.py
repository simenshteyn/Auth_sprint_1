import uuid
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from db.pg import db


class User(db.Model):
    query: db.Query  # added for type hinting
    __tablename__ = 'users'
    __table_args__ = {"schema": "app"}

    user_id = db.Column(UUID(as_uuid=True),
                        primary_key=True,
                        default=uuid.uuid4,
                        unique=True,
                        nullable=False)
    user_login = db.Column(db.String,
                           unique=True,
                           nullable=False)
    user_password = db.Column(db.String,
                              nullable=False)
    user_email = db.Column(db.String,
                           unique=True,
                           nullable=False)
    created_at = db.Column(db.DateTime(timezone=True),
                           server_default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True),
                           onupdate=func.now())

    def __repr__(self):
        return f'<User {self.user_login}>'
