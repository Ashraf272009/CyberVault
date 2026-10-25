
import os
import sqlite3
import tempfile
import unittest

from database import create_table, insert_login_event


class TestDatabase(unittest.TestCase):

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()

        create_table(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_insert_login_event(self):
        insert_login_event(
            "2026-10-19 09:15:22",
            "192.168.1.10",
            "ash",
            "SUCCESS",
            self.db_path
        )

        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()

        cursor.execute("""
            SELECT timestamp, ip, username, status
            FROM login_events
        """)

        row = cursor.fetchone()
        connection.close()

        self.assertEqual(
            row,
            ("2026-10-19 09:15:22", "192.168.1.10", "ash", "SUCCESS")
        )

    def test_table_starts_empty(self):
        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()

        cursor.execute("SELECT COUNT(*) FROM login_events")
        count = cursor.fetchone()[0]

        connection.close()

        self.assertEqual(count, 0)

    def test_duplicate_login_event_is_ignored(self):
        event = (
            "2026-10-19 09:15:22",
            "192.168.1.10",
            "ash",
            "SUCCESS",
        )

        first_result = insert_login_event(*event, db_path=self.db_path)
        second_result = insert_login_event(*event, db_path=self.db_path)

        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM login_events")
        count = cursor.fetchone()[0]
        connection.close()

        self.assertTrue(first_result)
        self.assertFalse(second_result)
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
