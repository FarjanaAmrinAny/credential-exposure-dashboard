from pathlib import Path
import re

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "authorized_exposure_input.csv"
OUTPUT_FILE = BASE_DIR / "detected_exposures.csv"
SAMPLE_FILE = BASE_DIR / "sample_exposures.csv"

REQUIRED_COLUMNS = {
    "record_id",
    "user_id",
    "department",
    "application",
    "credential_type",
    "exposure_source",
    "exposure_date",
    "evidence_reference",
    "exposure_confirmed",
    "privileged_account",
}

FORBIDDEN_COLUMNS = {
    "password",
    "raw_password",
    "password_value",
    "secret",
    "secret_value",
    "token",
    "token_value",
    "credential_value",
    "api_key_value",
    "access_token_value",
    "private_key_value",
}

OUTPUT_COLUMNS = [
    "finding_id",
    "user_id",
    "department",
    "application",
    "exposure_source",
    "exposure_date",
    "severity",
    "status",
    "credential_type",
    "evidence_reference",
    "privileged_account",
    "detection_reason",
]


def normalize_flag(value):
    value = str(value).strip().lower()

    if value in {"yes", "true", "1", "confirmed"}:
        return True
    if value in {"no", "false", "0", "unconfirmed"}:
        return False

    return None


def classify_risk(credential_type, privileged_account):
    credential_type = str(credential_type).strip().lower()
    privileged = normalize_flag(privileged_account)

    if privileged is True:
        return (
            "Critical",
            "Confirmed record is associated with a privileged account.",
        )

    if credential_type in {
        "api_key",
        "access_token",
        "private_key",
        "service_account",
    }:
        return (
            "High",
            "Confirmed sensitive credential type requires urgent review.",
        )

    if credential_type == "password":
        return (
            "Medium",
            "Confirmed password exposure requires review and rotation.",
        )

    return (
        "Low",
        "Credential type needs manual risk assessment.",
    )


def load_previous_statuses():
    statuses = {}

    # Preserve status updates across subsequent detector runs.
    for path in (SAMPLE_FILE, OUTPUT_FILE):
        if not path.exists():
            continue

        try:
            previous = pd.read_csv(path, dtype=str).fillna("")
        except (OSError, pd.errors.ParserError):
            continue

        if {"finding_id", "status"}.issubset(previous.columns):
            for _, row in previous.iterrows():
                finding_id = row["finding_id"].strip()
                status = row["status"].strip()

                if status in {"Open", "In Progress", "Resolved"}:
                    statuses[finding_id] = status

    return statuses


def validate_input(df):
    df.columns = [str(col).strip().lower() for col in df.columns]

    if len(df.columns) != len(set(df.columns)):
        raise ValueError("Duplicate CSV column names are not allowed.")

    forbidden = set(df.columns) & FORBIDDEN_COLUMNS
    if forbidden:
        raise ValueError(
            "Input contains prohibited raw-secret columns: "
            + ", ".join(sorted(forbidden))
            + ". Remove these columns; never supply actual secrets."
        )

    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(
            "Missing required columns: " + ", ".join(sorted(missing))
        )

    return df.fillna("")


def build_findings(df, previous_statuses=None):
    previous_statuses = previous_statuses or {}
    findings = []
    skipped = {
        "unconfirmed": 0,
        "invalid_confirmation": 0,
        "missing_metadata": 0,
        "invalid_privilege_flag": 0,
        "invalid_date": 0,
        "duplicate_id": 0,
    }

    seen_ids = set()

    for _, row in df.iterrows():
        record_id = str(row["record_id"]).strip()
        confirmed = normalize_flag(row["exposure_confirmed"])

        if confirmed is False:
            skipped["unconfirmed"] += 1
            continue

        if confirmed is not True:
            skipped["invalid_confirmation"] += 1
            continue

        privileged = normalize_flag(row["privileged_account"])
        if privileged is None:
            skipped["invalid_privilege_flag"] += 1
            continue

        required_values = [
            record_id,
            str(row["user_id"]).strip(),
            str(row["department"]).strip(),
            str(row["application"]).strip(),
            str(row["credential_type"]).strip(),
            str(row["exposure_source"]).strip(),
            str(row["evidence_reference"]).strip(),
        ]

        if not all(required_values):
            skipped["missing_metadata"] += 1
            continue

        if record_id in seen_ids:
            skipped["duplicate_id"] += 1
            continue

        date_value = pd.to_datetime(
            str(row["exposure_date"]).strip(),
            errors="coerce",
        )
        if pd.isna(date_value):
            skipped["invalid_date"] += 1
            continue

        seen_ids.add(record_id)

        match = re.fullmatch(r"R-(\d+)", record_id)
        finding_id = (
            f"F-{int(match.group(1)):03d}"
            if match
            else "F-" + re.sub(r"[^A-Za-z0-9_-]", "-", record_id)[:40]
        )

        severity, reason = classify_risk(
            row["credential_type"], privileged
        )

        findings.append({
            "finding_id": finding_id,
            "user_id": str(row["user_id"]).strip(),
            "department": str(row["department"]).strip(),
            "application": str(row["application"]).strip(),
            "exposure_source": str(row["exposure_source"]).strip(),
            "exposure_date": date_value.strftime("%Y-%m-%d"),
            "severity": severity,
            "status": previous_statuses.get(finding_id, "Open"),
            "credential_type": str(row["credential_type"]).strip(),
            "evidence_reference": str(row["evidence_reference"]).strip(),
            "privileged_account": "Yes" if privileged else "No",
            "detection_reason": reason,
        })

    result = pd.DataFrame(findings, columns=OUTPUT_COLUMNS)
    return result, skipped


def main():
    if not INPUT_FILE.exists():
        raise SystemExit(
            f"Input file not found: {INPUT_FILE.name}"
        )

    try:
        source = pd.read_csv(INPUT_FILE, dtype=str)
        source = validate_input(source)
        previous_statuses = load_previous_statuses()
        findings, skipped = build_findings(source, previous_statuses)
    except (OSError, ValueError, pd.errors.ParserError) as exc:
        raise SystemExit(f"Detection stopped: {exc}") from exc

    findings.to_csv(OUTPUT_FILE, index=False)

    print("Credential Exposure Detection complete")
    print("---------------------------------------")
    print(f"Input records: {len(source)}")
    print(f"Accepted findings: {len(findings)}")
    print(f"Output: {OUTPUT_FILE.name}")

    for reason, count in skipped.items():
        print(f"Skipped ({reason}): {count}")

    if not findings.empty:
        print("\nSeverity summary:")
        print(findings["severity"].value_counts().to_string())

    print(
        "\nNote: Findings are based on confirmation metadata "
        "in the supplied trusted/test dataset. "
        "This tool does not independently verify live exposure."
    )


if __name__ == "__main__":
    main()
