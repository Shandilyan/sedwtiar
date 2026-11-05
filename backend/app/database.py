import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

load_dotenv()

database_url_env = os.getenv("DATABASE_URL")
if database_url_env:
    database_url = database_url_env
    connect_args = {"check_same_thread": False} if str(database_url).startswith("sqlite") else {}
    engine = create_engine(database_url, connect_args=connect_args)
elif os.getenv("DB_HOST"):
    required_settings = ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD")
    missing_settings = [name for name in required_settings if not os.getenv(name)]

    if missing_settings:
        missing = ", ".join(missing_settings)
        raise RuntimeError(f"Missing required database settings: {missing}")

    database_url = URL.create(
        drivername="postgresql+psycopg",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        database=os.environ["DB_NAME"],
    )

    # Attempt PostgreSQL with a fast 2-second connect timeout; fallback to local SQLite if unreachable
    try:
        test_engine = create_engine(
            database_url,
            pool_pre_ping=True,
            connect_args={"connect_timeout": 2},
        )
        with test_engine.connect() as test_conn:
            pass
        engine = test_engine
    except Exception as exc:
        print(f"[Database Notice] Local PostgreSQL at {os.environ.get('DB_HOST')}:{os.environ.get('DB_PORT')} is not reachable. Falling back to local SQLite database: ./sedwtiar.db")
        database_url = "sqlite:///./sedwtiar.db"
        engine = create_engine(database_url, connect_args={"check_same_thread": False})
else:
    database_url = "sqlite:///./sedwtiar.db"
    engine = create_engine(database_url, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    """Base class inherited by every SQLAlchemy database model."""


def get_db():
    """Provide one database session per request and always close it afterwards."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
