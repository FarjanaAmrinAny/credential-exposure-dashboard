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

<img width="1920" height="901" alt="p2-1" src="https://github.com/user-attachments/assets/6fe5b6ef-a395-4231-8de2-225969080b41" />
<img width="1920" height="858" alt="P-2 2" src="https://github.com/user-attachments/assets/a4365f4e-4c09-4dba-a9e3-8663df389518" /><img width="1896" height="712" alt="p2-3" src="https://github.com/user-attachments/assets/aab5b6eb-9958-43f7-9bcb-952317410557" />
<img width="1920" height="852" alt="p2 4" src="https://github.com/user-attachments/assets/ae94ed68-1561-4123-96b0-a950c6130274" /><img width="1916" height="900" alt="pr2-HR" src="https://github.com/user-attachments/assets/e5968052-88b3-4ef5-b7cf-cd3ce994b108" />



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

