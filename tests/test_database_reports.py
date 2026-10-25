
import os
import sqlite3
import tempfile
import unittest

from database import (
    create_table,
    insert_login_event,
    get_login_summary,
    get_failed_logins_by_ip,
)


class TestDatabaseReports(unittest.TestCase):

    def setUp(self):
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.db_path = temp_file.name
        temp_file.close()

        create_table(self.db_path)

        insert_login_event(
            "2026-10-19 09:15:22",
            "192.168.1.10",
            "ash",
            "SUCCESS",
            self.db_path,
        )
        insert_login_event(
            "2026-10-19 09:16:03",
            "10.0.0.5",
            "admin",
            "FAILED",
            self.db_path,
        )
        insert_login_event(
            "2026-10-19 09:17:11",
            "10.0.0.5",
            "admin",
            "FAILED",
            self.db_path,
        )

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_login_summary(self):
        result = get_login_summary(self.db_path)

        self.assertEqual(
            result,
            {"SUCCESS": 1, "FAILED": 2},
        )

    def test_failed_logins_by_ip(self):
        result = get_failed_logins_by_ip(self.db_path)

        self.assertEqual(
            result,
            [("10.0.0.5", 2)],
        )


if __name__ == "__main__":
    unittest.main()
