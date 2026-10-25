# CyberVault — Cybersecurity Log Analyzer

CyberVault is a Python command-line project that parses login logs, validates events, identifies potentially suspicious login activity using simple rules, and stores unique events in an SQLite database.

This project was built for learning Python, file handling, input validation, SQL, database integration, and automated testing.

## Features

- **Log parsing and validation:** Reads login events and identifies malformed or invalid records.
- **Login statistics:** Counts successful and failed login events imported during the current run.
- **IP-based analysis:** Summarizes failed login attempts by IP address.
- **Rule-based detection:** Flags IP addresses with three or more newly imported failed login events during a run.
- **SQLite persistence:** Stores valid login events in a local database.
- **Duplicate prevention:** Skips events that match an existing timestamp, IP address, username, and status.
- **SQL reports:** Displays stored login summaries and failed-login counts by IP address.
- **Automated tests:** Uses Python's built-in `unittest` framework to test core logic, database operations, reporting, and repeated imports.

## Requirements

- Python 3
- No third-party Python packages are required.

Check your Python installation:

```bash
python --version
```

## Getting Started

1. Download or clone the repository.
2. Open a terminal in the project folder.
3. Run the analyzer:

```bash
python analyzer.py
```

The first run creates the SQLite database and imports valid, unique events from the sample log file. Run the command again to see duplicate events skipped.

## Generate Database Reports

To view summaries based on events stored in SQLite, run:

```bash
python database_reports.py
```

This displays the overall stored login counts and failed logins grouped by IP address.

## Run the Tests

Run the automated test suite from the project root:

```bash
python -m unittest discover -s tests -v
```

The tests cover log validation, event processing, duplicate handling, database operations, SQL reports, and repeated imports.

## Project Structure

```text
CyberVault/
├── analyzer.py
├── database.py
├── database_reports.py
├── data/
│   └── sample_logs.txt
├── tests/
│   ├── test_analyzer.py
│   ├── test_database.py
│   └── test_database_reports.py
├── .gitignore
└── README.md
```

The local SQLite database (`data/cybervault.db`) is generated when the project runs and is excluded from Git using `.gitignore`.

## Log Format

Each log event uses this format:

```text
YYYY-MM-DD HH:MM:SS | IP_ADDRESS | USERNAME | STATUS
```

Example:

```text
2026-10-19 09:16:03 | 192.168.1.15 | student | FAILED
2026-10-19 09:17:11 | 192.168.1.10 | ash | SUCCESS
```

The supported statuses are `SUCCESS` and `FAILED`. The sample log file also contains invalid entries so the analyzer's validation behavior can be tested.

## Duplicate Handling

CyberVault identifies duplicate events using these four fields:

- Timestamp
- IP address
- Username
- Status

When an identical event already exists in the database, the analyzer skips it. Only newly inserted events contribute to that run's imported-event statistics.

This is a simple educational deduplication strategy. In real log systems, distinct events can share the same four fields; a unique event ID or source-specific identifier would be preferable when available.

## Detection Logic and Limitations

CyberVault uses a simple threshold rule to flag IP addresses with at least three newly imported failed login events during a run.

This is an educational heuristic, not proof of malicious activity. Legitimate users can make repeated login mistakes, and real security monitoring requires additional context, time-based analysis, and carefully tuned detection rules.

The included logs are sample data. The project is not a production security monitoring system.

## Responsible Use

Use CyberVault only with logs you own or are authorized to analyze. Avoid including real usernames, passwords, personal information, or sensitive organizational data in public repositories.

## Future Improvements

Possible next steps include time-window-based detection, configurable thresholds, richer reports, and support for unique source event identifiers.
