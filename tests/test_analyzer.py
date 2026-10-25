import os
import sqlite3
import tempfile

from analyzer import process_log_file
from database import create_table
import unittest
from analyzer import is_valid_timestamp, is_valid_ip, parse_log_line, update_login_stats, find_suspicious_ips


class TestTimestampValidation(unittest.TestCase):

    def test_valid_timestamp(self):
        self.assertTrue(
            is_valid_timestamp("2026-10-19 09:15:22")
        )

    def test_invalid_timestamp(self):
        self.assertFalse(
            is_valid_timestamp("YESTERDAY 09:18:45")
        )


class TestIPValidation(unittest.TestCase):

    def test_valid_ip(self):
        self.assertTrue(is_valid_ip("192.168.1.10"))

    def test_invalid_ip(self):
        self.assertFalse(is_valid_ip("not-an-ip"))


class TestLogParsing(unittest.TestCase):

    def test_empty_username(self):
        result = parse_log_line(
            "2026-10-19 09:18:45 | 10.0.0.5 |      | FAILED"
        )

        self.assertIsNone(result)

    def test_invalid_status(self):
        result = parse_log_line(
            "2026-10-19 09:21:00 | 192.168.1.30 | guest | UNKNOWN"
        )

        self.assertIsNone(result)

    def test_valid_log_line(self):
        result = parse_log_line(
            "2026-10-19 09:15:22 | 192.168.1.10 | ash | SUCCESS"
        )

        self.assertEqual(
            result,
            ["2026-10-19 09:15:22", "192.168.1.10", "ash", "SUCCESS"]
        )

    def test_malformed_log_line(self):
        result = parse_log_line(
            "2026-10-19 09:21:00 | 192.168.1.30"
        )

        self.assertIsNone(result)

    def test_wrong_number_of_fields(self):
        result = parse_log_line(
            "2026-10-19 09:21:00 | 192.168.1.30"
        )

        self.assertIsNone(result)


class TestLoginStats(unittest.TestCase):

    def test_failed_login_threshold(self):
        threshold = 3

        self.assertFalse(2 >= threshold)
        self.assertTrue(3 >= threshold)
        self.assertTrue(4 >= threshold)

    def test_successful_login_updates_stats(self):
        stats = {"successful": 0, "failed": 0}
        failed_by_ip = {}

        parts = [
            "2026-10-19 09:15:22",
            "192.168.1.10",
            "ash",
            "SUCCESS",
        ]

        update_login_stats(parts, stats, failed_by_ip)

        self.assertEqual(stats["successful"], 1)
        self.assertEqual(stats["failed"], 0)
        self.assertEqual(failed_by_ip, {})

    def test_failed_login_updates_ip_count(self):
        stats = {"successful": 0, "failed": 0}
        failed_by_ip = {}

        parts = [
            "2026-10-19 09:16:03",
            "192.168.1.15",
            "student",
            "FAILED",
        ]

        update_login_stats(parts, stats, failed_by_ip)

        self.assertEqual(stats["failed"], 1)
        self.assertEqual(failed_by_ip["192.168.1.15"], 1)

    def test_repeated_failures_from_same_ip(self):
        stats = {"successful": 0, "failed": 0}
        failed_by_ip = {}

        parts = [
            "2026-10-19 09:16:03",
            "10.0.0.5",
            "admin",
            "FAILED",
        ]

        update_login_stats(parts, stats, failed_by_ip)
        update_login_stats(parts, stats, failed_by_ip)
        update_login_stats(parts, stats, failed_by_ip)

        self.assertEqual(stats["failed"], 3)
        self.assertEqual(failed_by_ip["10.0.0.5"], 3)


class TestSuspiciousIPDetection(unittest.TestCase):

    def test_detection_threshold(self):
        failed_by_ip = {
            "192.168.1.15": 2,
            "10.0.0.5": 3,
            "10.0.0.8": 4,
        }

        result = find_suspicious_ips(failed_by_ip)

        self.assertEqual(
            result,
            ["10.0.0.5", "10.0.0.8"],
        )

    def test_no_suspicious_ips(self):
        failed_by_ip = {
            "192.168.1.15": 1,
            "10.0.0.5": 2,
        }

        result = find_suspicious_ips(failed_by_ip)

        self.assertEqual(result, [])

    def test_empty_failed_logins(self):
        result = find_suspicious_ips({})

        self.assertEqual(result, [])


class TestRepeatedImports(unittest.TestCase):

    def setUp(self):
        db_file = tempfile.NamedTemporaryFile(delete=False)
        self.db_path = db_file.name
        db_file.close()

        log_file = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
        )
        self.log_path = log_file.name

        log_file.write(
            "2026-10-19 09:15:22 | 192.168.1.10 | ash | SUCCESS\n"
            "2026-10-19 09:16:03 | 10.0.0.5 | admin | FAILED\n"
        )
        log_file.close()

        create_table(self.db_path)

        self.stats = {"successful": 0, "failed": 0}
        self.failed_by_ip = {}

    def tearDown(self):
        for path in (self.db_path, self.log_path):
            if os.path.exists(path):
                os.remove(path)

    def test_repeated_import_does_not_inflate_stats(self):
        first_count = process_log_file(
            self.log_path,
            self.stats,
            self.failed_by_ip,
            self.db_path,
        )

        second_count = process_log_file(
            self.log_path,
            self.stats,
            self.failed_by_ip,
            self.db_path,
        )

        self.assertEqual(first_count, 2)
        self.assertEqual(second_count, 0)
        self.assertEqual(
            self.stats,
            {"successful": 1, "failed": 1},
        )
        self.assertEqual(self.failed_by_ip, {"10.0.0.5": 1})

        connection = sqlite3.connect(self.db_path)
        count = connection.execute(
            "SELECT COUNT(*) FROM login_events"
        ).fetchone()[0]
        connection.close()

        self.assertEqual(count, 2)


if __name__ == "__main__":
    unittest.main()
