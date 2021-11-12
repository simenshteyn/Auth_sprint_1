import uuid

from sqlalchemy import ForeignKey, FetchedValue
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from db import db


# create table auth_events
# (
#     auth_event_id          uuid                     default gen_random_uuid() not null
#         constraint auth_events_pkey
#             primary key,
#     auth_event_owner_id    uuid                                               not null
#         constraint auth_events_auth_event_owner_id_fkey
#             references users
#             on update cascade on delete cascade,
#     auth_event_type        app.auth_event_type,
#     auth_event_time        timestamp with time zone default now(),
#     auth_event_fingerprint text                                               not null
# );


class AuthEvent(db.Model):
    query: db.Query  # added for type hinting
    __tablename__ = 'auth_events'
    __table_args__ = {"schema": "app"}

    auth_event_id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    auth_event_owner_id = db.Column(UUID(as_uuid=True), db.ForeignKey("app.users.user_id"), nullable=False)
    auth_event_time = db.Column(db.DateTime(timezone=True), server_default=func.now())
    auth_event_fingerprint = db.Column(db.String, nullable=False)

