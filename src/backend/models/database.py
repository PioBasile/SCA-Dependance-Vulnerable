"""Database models using SQLAlchemy ORM."""
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, 
    ForeignKey, JSON, DECIMAL, Boolean, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.pool import QueuePool

from core.config import settings
from core.logger import get_logger

logger = get_logger(__name__)

# Database setup
engine = create_engine(
    settings.database.url,
    echo=settings.database.echo,
    poolclass=QueuePool,
    pool_size=settings.database.pool_size,
    max_overflow=settings.database.max_overflow,
    pool_recycle=3600,  # Recycle connections after 1 hour
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Session:
    """Dependency for FastAPI to inject database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================================
# ORM Models
# ============================================================================

class CveItem(Base):
    """Main CVE vulnerability record."""
    __tablename__ = "cve"
    
    cve_id = Column(String(255), primary_key=True)
    euvd_id = Column(String(255), nullable=True, unique=True)
    sourceIdentifier = Column("source_identifier", String(255), nullable=False)
    vulnStatus = Column("vuln_status", String(255), nullable=False, default="PUBLISHED")
    published = Column(DateTime, nullable=False, default=datetime.utcnow)
    lastModified = Column("last_modified", DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    descriptions = relationship("Description", back_populates="cve_item", cascade="all, delete-orphan")
    references = relationship("Reference", back_populates="cve_item", cascade="all, delete-orphan")
    cvss_metrics = relationship("CvssMetric", back_populates="cve_item", cascade="all, delete-orphan")
    nodes = relationship("Node", back_populates="cve_item", cascade="all, delete-orphan")
    __table_args__ = (
        Index("idx_cve_euvd", "euvd_id"),
        Index("idx_cve_status", "vuln_status"),
    )


class Description(Base):
    """CVE description in multiple languages."""
    __tablename__ = "description"
    
    id = Column("description_id", Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(255), ForeignKey("cve.cve_id", ondelete="CASCADE"), nullable=False)
    lang = Column(String(5), nullable=False, default="en", index=True)
    value = Column(Text, nullable=False)
    
    # Relationships
    cve_item = relationship("CveItem", back_populates="descriptions")
    
    __table_args__ = (
        Index("idx_desc_cve_lang", "cve_id", "lang"),
    )


class Reference(Base):
    """CVE reference URLs and sources."""
    __tablename__ = "reference"
    
    id = Column("reference_id", Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(255), ForeignKey("cve.cve_id", ondelete="CASCADE"), nullable=False)
    url = Column(String(500), nullable=False)
    source = Column(String(255), nullable=True)
    tags = Column(JSON, nullable=True, default=[])
    
    # Relationships
    cve_item = relationship("CveItem", back_populates="references")
    
    __table_args__ = (
        Index("idx_ref_cve", "cve_id"),
    )


class CvssMetric(Base):
    """CVSS scoring data (v3.0, v3.1, v4.0, etc.)."""
    __tablename__ = "cvss_metrics"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(255), ForeignKey("cve.cve_id", ondelete="CASCADE"), nullable=False)
    version = Column(String(10), nullable=False, default="3.1")  # "3.0", "3.1", "4.0"
    cvssData = Column(JSON, nullable=False)  # Contains baseScore, vectorString, version
    exploitabilityScore = Column(DECIMAL(3, 1), nullable=True)
    impactScore = Column(DECIMAL(3, 1), nullable=True)
    source = Column(String(255), nullable=False)  # "EUVD", "NVD", "OSV", etc.
    type = Column(String(50), nullable=True, default="Primary")  # Primary or Secondary
    
    # Relationships
    cve_item = relationship("CveItem", back_populates="cvss_metrics")
    
    __table_args__ = (
        Index("idx_cvss_cve", "cve_id"),
        Index("idx_cvss_version", "version"),
    )


class Node(Base):
    """CPE vulnerability configuration node."""
    __tablename__ = "node"
    
    id = Column("node_id", Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(255), ForeignKey("cve.cve_id", ondelete="CASCADE"), nullable=False)
    operator = Column(String(10), nullable=False, default="OR")  # AND, OR
    negate = Column(Boolean, nullable=False, default=False)
    
    # Relationships
    cve_item = relationship("CveItem", back_populates="nodes")
    cpe_matches = relationship("CpeMatch", back_populates="node", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index("idx_node_cve", "cve_id"),
    )


class CpeMatch(Base):
    """CPE match criteria for vulnerability."""
    __tablename__ = "cpe"
    
    id = Column("cpe_id", Integer, primary_key=True, autoincrement=True)
    node_id = Column(Integer, ForeignKey("node.node_id", ondelete="CASCADE"), nullable=False)
    vulnerable = Column(Boolean, nullable=False, default=True)
    criteria = Column(String(500), nullable=False, index=True)
    matchCriteriaId = Column(String(50), nullable=True)
    versionStartIncluding = Column(String(100), nullable=True)
    versionEndIncluding = Column(String(100), nullable=True)
    versionStartExcluding = Column(String(100), nullable=True)
    versionEndExcluding = Column(String(100), nullable=True)
    scanned_at = Column(DateTime, nullable=True)
    
    # Relationships
    node = relationship("Node", back_populates="cpe_matches")
    
    __table_args__ = (
        Index("idx_cpe_node", "node_id"),
        Index("idx_cpe_criteria", "criteria"),
    )


# ============================================================================
# Database initialization
# ============================================================================

def init_db():
    """Create all tables."""
    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables initialized")
