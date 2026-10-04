import json
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from flowsint_core.core.enums import EventLevel
from flowsint_core.core.types import Role


class RoleListType(TypeDecorator):
    """Stores a list of Role enums as a JSON string. Portable across dialects."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Optional[List[Any]], dialect: Dialect) -> str:
        if value is not None:
            return json.dumps([r.value if isinstance(r, Role) else r for r in value])
        return "[]"

    def process_result_value(
        self, value: Optional[str], dialect: Dialect
    ) -> List[Role]:
        if value is not None:
            return [Role(r.lower()) for r in json.loads(value)]
        return []


class Base(DeclarativeBase):
    pass


class Feedback(Base):
    __tablename__ = "feedbacks"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    content = mapped_column(Text, nullable=True)
    owner_id = mapped_column(Uuid, ForeignKey("profiles.id"), nullable=True)


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    name = mapped_column(Text)
    description = mapped_column(Text)
    owner_id = mapped_column(
        Uuid,
        ForeignKey("profiles.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    last_updated_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    status = mapped_column(String, server_default="active")
    sketches = relationship("Sketch", back_populates="investigation")
    analyses = relationship("Analysis", back_populates="investigation")
    chats = relationship("Chat", back_populates="investigation")
    owner = relationship("Profile", foreign_keys=[owner_id])
    user_roles = relationship(
        "InvestigationUserRole",
        back_populates="investigation",
        passive_deletes=True,
        cascade="save-update, merge",
    )
    __table_args__ = (
        Index("idx_investigations_id", "id"),
        Index("idx_investigations_owner_id", "owner_id"),
    )


class Log(Base):
    __tablename__ = "logs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    content = mapped_column(JSON, nullable=True)
    # Allow both server-side default and application-side timestamp
    created_at = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )
    sketch_id = mapped_column(
        Uuid,
        ForeignKey("sketches.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    # Legacy Column() declarative style (not mapped_column/Mapped[...] like
    # the rest of this class) — no sqlalchemy mypy plugin configured to
    # infer its Python-side type, so mypy sees Column[Never] here.
    type: Any = Column(SQLEnum(EventLevel), default=EventLevel.INFO)


class Profile(Base):
    __tablename__ = "profiles"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    first_name = mapped_column(Text, nullable=True)
    last_name = mapped_column(Text, nullable=True)
    avatar_url = mapped_column(Text, nullable=True)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True)
    investigation_roles = relationship("InvestigationUserRole", back_populates="user")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    sketch_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("sketches.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    # Same legacy Column() style as Log.type above.
    status: Any = Column(SQLEnum(EventLevel), default=EventLevel.PENDING)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    details = Column(JSON, nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Relationships
    sketch = relationship("Sketch", back_populates="scans")

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, status={self.status})>"


class AgentRun(Base):
    """One autonomous passive investigation: objective, budget, steps, report."""

    __tablename__ = "agent_runs"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    sketch_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("sketches.id", ondelete="CASCADE"), index=True
    )
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("profiles.id", ondelete="SET NULL")
    )
    objective: Mapped[str] = mapped_column(Text)
    seed_ids: Mapped[list] = mapped_column(JSON, default=list)
    # running -> publishing -> completed; running -> cancelled; any active -> failed
    status: Mapped[str] = mapped_column(String, default="running")
    max_steps: Mapped[int] = mapped_column(Integer, default=20)
    steps: Mapped[list] = mapped_column(JSON, default=list)
    report: Mapped[str | None] = mapped_column(Text, nullable=True)
    finding_ids: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Set when the worker picks the run up; NULL while it is still queued.
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Sketch(Base):
    __tablename__ = "sketches"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    title = mapped_column(Text)
    description = mapped_column(Text)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    owner_id = mapped_column(
        Uuid,
        ForeignKey("profiles.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    status = mapped_column(String, server_default="active")
    investigation_id = mapped_column(
        Uuid,
        ForeignKey("investigations.id", onupdate="CASCADE", ondelete="CASCADE"),
    )
    investigation = relationship("Investigation", back_populates="sketches")
    last_updated_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    scans = relationship("Scan", back_populates="sketch")

    __table_args__ = (
        Index("idx_sketches_investigation_id", "investigation_id"),
        Index("idx_sketches_owner_id", "owner_id"),
    )


class SketchesProfiles(Base):
    __tablename__ = "sketches_profiles"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    profile_id = mapped_column(
        Uuid,
        ForeignKey("profiles.id", onupdate="CASCADE", ondelete="CASCADE"),
    )
    sketch_id = mapped_column(
        Uuid,
        ForeignKey("sketches.id", onupdate="CASCADE", ondelete="CASCADE"),
    )
    role = mapped_column(String, server_default="editor")

    __table_args__ = (
        Index("idx_sketches_profiles_sketch_id", "sketch_id"),
        Index("idx_sketches_profiles_profile_id", "profile_id"),
        Index(
            "investigations_profiles_unique_profile_investigation",
            "profile_id",
            "sketch_id",
            unique=True,
        ),
    )


class Flow(Base):
    __tablename__ = "flows"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name = mapped_column(Text, nullable=False)
    description = mapped_column(Text, nullable=True)
    category = mapped_column(JSON, nullable=True)
    flow_schema = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_updated_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    owner_id = mapped_column(
        Uuid,
        ForeignKey("profiles.id", onupdate="CASCADE", ondelete="SET NULL"),
        nullable=True,
    )


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    title = mapped_column(Text, nullable=False)
    description = mapped_column(Text, nullable=True)
    content = mapped_column(JSON, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    __mapper_args__ = {"version_id_col": version}
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_updated_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    owner_id = mapped_column(
        Uuid,
        ForeignKey("profiles.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    investigation_id = mapped_column(
        Uuid,
        ForeignKey("investigations.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    investigation = relationship("Investigation", back_populates="analyses")

    __table_args__ = (
        Index("idx_analyses_owner_id", "owner_id"),
        Index("idx_analyses_investigation_id", "investigation_id"),
    )


class Chat(Base):
    __tablename__ = "chats"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    title = mapped_column(Text, nullable=False)
    description = mapped_column(Text, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_updated_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    owner_id = mapped_column(
        Uuid,
        ForeignKey("profiles.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    investigation_id = mapped_column(
        Uuid,
        ForeignKey("investigations.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    investigation = relationship("Investigation", back_populates="chats")
    messages = relationship("ChatMessage", back_populates="chat", cascade="all, delete")
    __table_args__ = (
        Index("idx_chats_owner_id", "owner_id"),
        Index("idx_chats_investigation_id", "investigation_id"),
    )


class ChatMessage(Base):
    __tablename__ = "messages"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    content = mapped_column(JSON, nullable=True)
    context = mapped_column(JSON, nullable=True)
    is_bot: Mapped[bool] = mapped_column(default=False)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    chat_id = mapped_column(
        Uuid,
        ForeignKey("chats.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False,
    )
    chat = relationship("Chat", back_populates="messages")
    __table_args__ = (Index("idx_messages_chat_id", "chat_id"),)


class Key(Base):
    __tablename__ = "keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    name: Mapped[str] = mapped_column(String, nullable=False)  # ex: "shodan", "whocy"

    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("profiles.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False,
    )

    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    iv: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # 12 bytes
    salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # 16/32 bytes
    key_version: Mapped[str] = mapped_column(String, nullable=False)  # ex: "V1"

    created_at: Mapped[str] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("idx_keys_owner_id", "owner_id"),
        Index("idx_keys_service", "name"),
    )


class InvestigationUserRole(Base):
    __tablename__ = "investigation_user_roles"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("profiles.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False,
    )

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("investigations.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False,
    )

    roles: Mapped[list[Role]] = mapped_column(
        RoleListType(),
        nullable=False,
        default=list,
    )

    # Relations ORM
    user = relationship(
        "Profile", back_populates="investigation_roles", passive_deletes=True
    )
    investigation = relationship(
        "Investigation", back_populates="user_roles", passive_deletes=True
    )

    __table_args__ = (
        UniqueConstraint("user_id", "investigation_id", name="uq_user_investigation"),
        Index("idx_investigation_roles_user_id", "user_id"),
        Index("idx_investigation_roles_investigation_id", "investigation_id"),
    )


class CustomType(Base):
    __tablename__ = "custom_types"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("profiles.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False,
    )
    schema: Mapped[dict] = mapped_column(JSON, nullable=False)
    icon: Mapped[str] = mapped_column(String, nullable=True)
    color: Mapped[str] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, server_default="draft", nullable=False)
    category: Mapped[str] = mapped_column(
        String, server_default="custom_types_category", nullable=False
    )
    checksum: Mapped[str] = mapped_column(String, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    owner = relationship("Profile", foreign_keys=[owner_id])

    __table_args__ = (
        Index("idx_custom_types_owner_id", "owner_id"),
        Index("idx_custom_types_name", "name"),
        Index("idx_custom_types_status", "status"),
    )


class EnricherTemplate(Base):
    __tablename__ = "enricher_templates"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    content: Mapped[dict] = mapped_column(JSON, nullable=False)
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("profiles.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    owner = relationship("Profile", foreign_keys=[owner_id])

    __table_args__ = (
        Index("idx_enricher_templates_owner_id", "owner_id"),
        Index("idx_enricher_templates_name", "name"),
        Index("idx_enricher_templates_category", "category"),
        Index("idx_enricher_templates_is_public", "is_public"),
    )


class CaseItem(Base):
    """An investigative question, finding, or comment with a review trail."""

    __tablename__ = "case_items"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("profiles.id", ondelete="SET NULL")
    )
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("profiles.id", ondelete="SET NULL")
    )
    reviewer_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("profiles.id", ondelete="SET NULL")
    )
    sketch_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("sketches.id", ondelete="CASCADE")
    )
    target_kind: Mapped[str | None] = mapped_column(String)
    target_id: Mapped[str | None] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String)
    body: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text, default="", server_default="")
    assessment: Mapped[str] = mapped_column(Text, default="", server_default="")
    decision: Mapped[str] = mapped_column(
        String, default="pending", server_default="pending"
    )
    status: Mapped[str] = mapped_column(String, default="open", server_default="open")
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    __mapper_args__ = {"version_id_col": version}


class CaseActivity(Base):
    __tablename__ = "case_activity"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("profiles.id", ondelete="SET NULL")
    )
    actor_name: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)
    item_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    details: Mapped[dict] = mapped_column(JSON)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
