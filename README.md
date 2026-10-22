# Credential Exposure Dashboard

A SOC Analyst portfolio project for triaging simulated credential-exposure
findings, mapping identities to departments and applications, and tracking
remediation status.

## Features

- Processes authorized or synthetic exposure metadata.
- Skips records marked as unconfirmed.
- Validates required fields and evidence references.
- Assigns basic risk severity using credential type and privileged-account
  metadata.
- Maps test user IDs to departments and applications.
- Provides dashboard filters, charts, search, and findings tables.
- Tracks Open, In Progress, and Resolved remediation states.
- Rejects input CSVs containing prohibited raw-secret columns.
- Includes automated unit tests.

## Technology Stack

- Python
- Pandas
- Streamlit
- Plotly
- CSV
- unittest

## Project Structure

```text
credential-exposure-dashboard/
├── dashboard.py
├── detect_exposures.py
├── authorized_exposure_input.csv
├── detected_exposures.csv
├── sample_exposures.csv
├── requirements.txt
├── README.md
├── .gitignore
└── tests/
    └── test_detect_exposures.py

