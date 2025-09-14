from sqlmodel import create_engine, Session, SQLModel

# Define the database URL for SQLite
# The database will be created in the root of the project as `database.db`
DATABASE_URL = "sqlite:///../../database.db"

# Create the database engine
# `connect_args` is needed for SQLite to enforce foreign key constraints
engine = create_engine(DATABASE_URL, echo=True, connect_args={"check_same_thread": False})


def get_session():
    """
    Dependency to get a database session.
    This will be used in the API endpoints.
    """
    with Session(engine) as session:
        yield session


def create_db_and_tables():
    """
    Utility function to create the database and all tables.
    This can be called once at the startup of the application.
    """
    SQLModel.metadata.create_all(engine)
