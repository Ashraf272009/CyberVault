
from database import get_login_summary, get_failed_logins_by_ip


def show_login_summary():
    results = get_login_summary()

    print("\n--- Database Login Summary ---")

    for status in ("SUCCESS", "FAILED"):
        print(f"{status} logins: {results.get(status, 0)}")


def show_failed_logins_by_ip():
    results = get_failed_logins_by_ip()

    print("\n--- Failed Logins by IP ---")

    if not results:
        print("No failed logins recorded.")
        return

    for ip, count in results:
        print(f"{ip}: {count}")


if __name__ == "__main__":
    show_login_summary()
    show_failed_logins_by_ip()
