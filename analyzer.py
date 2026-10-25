from datetime import datetime
import ipaddress
from database import create_table, insert_login_event


FAILED_LOGIN_THRESHOLD = 3

create_table()


def is_valid_timestamp(timestamp):
    try:
        datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        return True
    except ValueError:
        return False


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_username(username):
    return bool(username.strip())


def is_valid_status(status):
    return status in ["SUCCESS", "FAILED"]


def parse_log_line(line):
    clean_line = line.strip()
    parts = clean_line.split("|")

    if len(parts) != 4:
        print("Invalid log entry:", clean_line)
        return None

    parts = [part.strip() for part in parts]

    if not is_valid_timestamp(parts[0]):
        print("Invalid timestamp in log entry:", clean_line)
        return None

    if not is_valid_ip(parts[1]):
        print("Invalid IP address in log entry:", clean_line)
        return None

    if not is_valid_username(parts[2]):
        print("Invalid username in log entry:", clean_line)
        return None

    if not is_valid_status(parts[3]):
        print("Invalid status in log entry:", clean_line)
        return None

    return parts


def update_login_stats(parts, stats, failed_by_ip):
    if parts[3] == "SUCCESS":
        stats["successful"] += 1
    else:
        stats["failed"] += 1

        ip = parts[1]
        if ip in failed_by_ip:
            failed_by_ip[ip] += 1
        else:
            failed_by_ip[ip] = 1


def find_suspicious_ips(failed_by_ip):
    suspicious_ips = []

    for ip, count in failed_by_ip.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            suspicious_ips.append(ip)

    return suspicious_ips


def process_log_file(
    file_path,
    stats,
    failed_by_ip,
    db_path="data/cybervault.db",
):
    create_table(db_path)
    inserted_count = 0

    with open(file_path, "r") as file:
        for line in file:
            parts = parse_log_line(line)

            if parts is None:
                continue

            inserted = insert_login_event(
                parts[0],
                parts[1],
                parts[2],
                parts[3],
                db_path=db_path,
            )

            if not inserted:
                print("Duplicate event skipped:", parts)
                continue

            print(parts[0], parts[1], parts[2], parts[3])
            update_login_stats(parts, stats, failed_by_ip)
            inserted_count += 1

    return inserted_count


def main():
    stats = {
        "successful": 0,
        "failed": 0
    }
    failed_by_ip = {}

    process_log_file(
        "data/sample_logs.txt",
        stats,
        failed_by_ip,
    )

    print("\n--- Login Summary ---")
    print("Successful logins:", stats["successful"])
    print("Failed logins:", stats["failed"])

    print("\n--- Failed Logins by IP ---")
    for ip, count in failed_by_ip.items():
        print(f"{ip}: {count}")

    print("\n--- Security Alerts ---")
    suspicious_ips = find_suspicious_ips(failed_by_ip)

    for ip in suspicious_ips:
        print(
            "ALERT:",
            ip,
            "had",
            failed_by_ip[ip],
            "failed login attempts"
        )


if __name__ == "__main__":
    main()
