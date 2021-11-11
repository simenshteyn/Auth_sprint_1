from sqlalchemy.dialects.postgresql import UUID

from db.pg import db


class User(db.Model):
    __tablename__ = 'roles'

    role_id = db.Column(UUID(as_uuid=True), primary_key=True, unique=True,
                        nullable=False)
    role_name = db.Column(db.String, unique=True, nullable=False)

    def __repr__(self):
        return f'<Role {self.role_name}>'
