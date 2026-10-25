
import sqlite3

DATABASE_PATH = "data/cybervault.db"


def create_table(db_path=DATABASE_PATH):
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            username TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'FAILED'))
        )
    """)

    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_login_event
        ON login_events (timestamp, ip, username, status)
    """)

    connection.commit()
    connection.close()


def insert_login_event(timestamp, ip, username, status, db_path=DATABASE_PATH):
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO login_events (timestamp, ip, username, status)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(timestamp, ip, username, status) DO NOTHING
    """, (timestamp, ip, username, status))

    inserted = cursor.rowcount == 1

    connection.commit()
    connection.close()

    return inserted


def get_login_summary(db_path=DATABASE_PATH):
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT status, COUNT(*)
        FROM login_events
        GROUP BY status
    """)

    results = cursor.fetchall()
    connection.close()

    return dict(results)


def get_failed_logins_by_ip(db_path=DATABASE_PATH):
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT ip, COUNT(*)
        FROM login_events
        WHERE status = 'FAILED'
        GROUP BY ip
        ORDER BY COUNT(*) DESC, ip ASC
    """)

    results = cursor.fetchall()
    connection.close()

    return results


if __name__ == "__main__":
    create_table()
    print("Database table created successfully.")
