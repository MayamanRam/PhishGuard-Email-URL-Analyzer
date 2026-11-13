"""SQLAlchemy Base Declarative Model Configuration."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models in PhishGuard."""
    pass

