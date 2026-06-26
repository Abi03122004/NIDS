from werkzeug.security import generate_password_hash, check_password_hash
from database import get_connection
from datetime import datetime, timezone

class User:
    def __init__(self, user_id, username, email, password_hash, created_at):
        self.id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.created_at = created_at

    @staticmethod
    def get(user_id: int):
        """Retrieves a user by their unique ID."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, email, password_hash, created_at FROM users WHERE id = ?",
                (int(user_id),)
            )
            row = cursor.fetchone()
            if row:
                return User(row['id'], row['username'], row['email'], row['password_hash'], row['created_at'])
        return None

    @staticmethod
    def get_by_email(email: str):
        """Retrieves a user by their email address."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, email, password_hash, created_at FROM users WHERE email = ?",
                (email.strip().lower(),)
            )
            row = cursor.fetchone()
            if row:
                return User(row['id'], row['username'], row['email'], row['password_hash'], row['created_at'])
        return None

    @staticmethod
    def create(username: str, email: str, password_raw: str):
        """Creates a new user with a hashed password."""
        password_hash = generate_password_hash(password_raw)
        created_at = datetime.now(timezone.utc).isoformat()
        with get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (username.strip(), email.strip().lower(), password_hash, created_at)
                )
                conn.commit()
                return cursor.lastrowid
            except Exception as e:
                print(f"Error creating user: {e}")
                return None

    def check_password(self, password_raw: str) -> bool:
        """Verifies if the raw password matches the saved hash."""
        return check_password_hash(self.password_hash, password_raw)

    @staticmethod
    def get_all():
        """Retrieves all registered users."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, created_at FROM users ORDER BY username ASC")
            return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def delete(user_id: int) -> bool:
        """Deletes a user by their unique ID."""
        with get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM users WHERE id = ?", (int(user_id),))
                conn.commit()
                return True
            except Exception as e:
                print(f"Error deleting user: {e}")
                return False
