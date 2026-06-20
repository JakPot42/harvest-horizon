"""conftest.py — set DATABASE_URL before any imports to use a throwaway test DB."""

import os
import tempfile

# Must set before importing anything that imports config or database
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}"
os.environ["DEMO_MODE"] = "True"
os.environ["ANTHROPIC_API_KEY"] = ""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base, get_db
from main import app
from seed_data import load_seed_data


@pytest.fixture(scope="session")
def db_engine():
    engine = create_engine(
        f"sqlite:///{_tmp.name}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture(scope="session")
def db_session(db_engine):
    Session = sessionmaker(bind=db_engine)
    session = Session()
    load_seed_data(session)
    yield session
    session.close()


@pytest.fixture(scope="session")
def client(db_engine):
    Session = sessionmaker(bind=db_engine)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=db_engine)
    # Seed once
    s = Session()
    load_seed_data(s)
    s.close()
    with TestClient(app) as c:
        yield c
