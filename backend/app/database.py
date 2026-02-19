from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./muleguard.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class SuspiciousHistory(Base):
    __tablename__ = "suspicious_history"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(String, index=True)
    last_score = Column(Float)
    times_flagged = Column(Integer)
    last_flagged_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)
