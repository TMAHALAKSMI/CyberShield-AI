"""
SQLAlchemy ORM Models for Phishing Detection App
Tables: users, scan_history, login_history
"""

from sqlalchemy import (
    Column, Integer, String, Boolean, Float,
    DateTime, ForeignKey, Text
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database.db import Base


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String(50),  unique=True, nullable=False, index=True)
    email         = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    is_active     = Column(Boolean, default=True)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())
    updated_at    = Column(DateTime(timezone=True), onupdate=func.now())

    # relationships
    scans         = relationship("ScanHistory",  back_populates="user", cascade="all, delete-orphan")
    login_logs    = relationship("LoginHistory", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User id={self.id} username={self.username}>"


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id            = Column(Integer, primary_key=True, index=True)
    user_id       = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    url           = Column(Text, nullable=False)
    is_phishing   = Column(Boolean, nullable=False)
    prediction    = Column(String(20), nullable=False)          # "phishing" | "legitimate"
    confidence    = Column(Float,   nullable=False)
    scanned_at    = Column(DateTime(timezone=True), server_default=func.now())

    # relationship
    user          = relationship("User", back_populates="scans")

    def __repr__(self):
        return f"<ScanHistory id={self.id} url={self.url[:40]} prediction={self.prediction}>"


class LoginHistory(Base):
    __tablename__ = "login_history"

    id            = Column(Integer, primary_key=True, index=True)
    user_id       = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    ip_address    = Column(String(45),  nullable=True)   # IPv4 / IPv6
    user_agent    = Column(String(256), nullable=True)
    success       = Column(Boolean, default=True)
    logged_in_at  = Column(DateTime(timezone=True), server_default=func.now())

    # relationship
    user          = relationship("User", back_populates="login_logs")

    def __repr__(self):
        return f"<LoginHistory id={self.id} user_id={self.user_id} success={self.success}>"