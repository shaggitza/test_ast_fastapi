"""
Database Session Dependencies Example

This example demonstrates database session management patterns,
including session lifecycle, transactions, and cleanup.
"""

from typing import Annotated, Generator

from fastapi import Depends, FastAPI, HTTPException

app = FastAPI(title="Database Session Example")


class Database:
    """Simulated database connection."""

    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.connected = False

    def connect(self) -> None:
        """Open database connection."""
        self.connected = True

    def disconnect(self) -> None:
        """Close database connection."""
        self.connected = False

    def execute(self, query: str) -> list:
        """Execute a query."""
        if not self.connected:
            raise RuntimeError("Database not connected")
        # Simulate query execution
        return []


class Session:
    """Database session with transaction support."""

    def __init__(self, db: Database):
        self.db = db
        self.in_transaction = False

    def begin(self) -> None:
        """Start a transaction."""
        self.in_transaction = True

    def commit(self) -> None:
        """Commit the current transaction."""
        if self.in_transaction:
            self.in_transaction = False

    def rollback(self) -> None:
        """Rollback the current transaction."""
        if self.in_transaction:
            self.in_transaction = False

    def query(self, model: str) -> list:
        """Execute a query on the given model."""
        return self.db.execute(f"SELECT * FROM {model}")


# Global database instance (in real app, configure properly)
database = Database("postgresql://user:pass@localhost/db")


def get_db_session() -> Generator[Session, None, None]:
    """
    Dependency that provides a database session.
    Automatically handles connection and cleanup.
    """
    if not database.connected:
        database.connect()

    session = Session(database)
    try:
        yield session
    finally:
        # Cleanup: rollback any uncommitted transactions
        if session.in_transaction:
            session.rollback()


def get_transactional_session() -> Generator[Session, None, None]:
    """
    Dependency that provides a session with automatic transaction management.
    Commits on success, rolls back on exception.
    """
    if not database.connected:
        database.connect()

    session = Session(database)
    session.begin()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise


# Type aliases
DBSession = Annotated[Session, Depends(get_db_session)]
TransactionalSession = Annotated[Session, Depends(get_transactional_session)]


@app.get("/users")
def get_users(session: DBSession) -> dict:
    """Get all users using a database session."""
    users = session.query("users")
    return {"users": users, "count": len(users)}


@app.get("/users/{user_id}")
def get_user(user_id: int, session: DBSession) -> dict:
    """Get a specific user by ID."""
    users = session.query("users")
    # Simulate finding user
    user = {"id": user_id, "name": f"User {user_id}"}
    return {"user": user}


@app.post("/users")
def create_user(user_data: dict, session: TransactionalSession) -> dict:
    """
    Create a new user with automatic transaction management.
    Transaction is committed on success, rolled back on error.
    """
    # Simulate user creation
    new_user = {"id": 123, **user_data}

    # In real app, add to session and flush
    # session.add(new_user)
    # session.flush()

    return {"user": new_user, "created": True}


@app.put("/users/{user_id}")
def update_user(
    user_id: int, user_data: dict, session: TransactionalSession
) -> dict:
    """Update user with automatic transaction management."""
    # Simulate update
    updated_user = {"id": user_id, **user_data}
    return {"user": updated_user, "updated": True}


@app.delete("/users/{user_id}")
def delete_user(user_id: int, session: TransactionalSession) -> dict:
    """Delete user with automatic transaction management."""
    # Simulate deletion
    return {"deleted": True, "user_id": user_id}
