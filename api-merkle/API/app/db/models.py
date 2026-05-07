from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text

from .database import Base


def utc_now() -> datetime:
    """
    Devuelve la fecha/hora actual en UTC con zona horaria explícita.
    """
    return datetime.now(timezone.utc)


class RegistryEntry(Base):
    __tablename__ = "registry_entries"

    id = Column(Integer, primary_key=True, index=True)
    identity = Column(String, index=True, nullable=False)
    public_key = Column(Text, nullable=False)
    metadata_json = Column(Text, nullable=False)

    valid_from = Column(String, nullable=True)
    valid_until = Column(String, nullable=True)

    leaf_hash = Column(String, nullable=False)

    status = Column(String, default="active", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    tree_version = Column(Integer, nullable=False)


class SignedRoot(Base):
    __tablename__ = "signed_roots"

    id = Column(Integer, primary_key=True, index=True)
    tree_version = Column(Integer, nullable=False)
    tree_size = Column(Integer, nullable=False)

    merkle_root = Column(String, nullable=False)
    signature = Column(Text, nullable=False)
    public_key = Column(Text, nullable=False)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)