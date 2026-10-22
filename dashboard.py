from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(
    page_title="Credential Exposure Dashboard",
    page_icon="🔐",
    layout="wide",
)

DATA_FILE = Path(__file__).with_name("detected_exposures.csv")

st.title("🔐 Credential Exposure Dashboard")
st.caption("SOC Analyst Lab | Synthetic test data only")

if not DATA_FILE.exists():
    st.error("sample_exposures.csv file not found.")
    st.stop()

df = pd.read_csv(DATA_FILE)

required = {
    "finding_id", "user_id", "department", "application",
    "exposure_source", "exposure_date", "severity", "status"
}

if not required.issubset(df.columns):
    st.error("Dataset columns are missing. Check sample_exposures.csv.")
    st.stop()

df["exposure_date"] = pd.to_datetime(
    df["exposure_date"], errors="coerce"
)

severity_order = ["Critical", "High", "Medium", "Low"]
status_order = ["Open", "In Progress", "Resolved"]

st.sidebar.header("Filters")

departments = st.sidebar.multiselect(
    "Department",
    sorted(df["department"].dropna().unique()),
)

severities = st.sidebar.multiselect(
    "Severity",
    severity_order,
    default=severity_order,
)

statuses = st.sidebar.multiselect(
    "Remediation Status",
    status_order,
    default=status_order,
)

search = st.sidebar.text_input(
    "Search user, finding or application"
).strip().lower()

filtered = df.copy()

if departments:
    filtered = filtered[filtered["department"].isin(departments)]

if severities:
    filtered = filtered[filtered["severity"].isin(severities)]
else:
    filtered = filtered.iloc[0:0]

if statuses:
    filtered = filtered[filtered["status"].isin(statuses)]
else:
    filtered = filtered.iloc[0:0]

if search:
    searchable = (
        filtered["finding_id"].fillna("").astype(str)
        + " " + filtered["user_id"].fillna("").astype(str)
        + " " + filtered["application"].fillna("").astype(str)
    ).str.lower()
    filtered = filtered[searchable.str.contains(search, regex=False)]

critical_count = (filtered["severity"] == "Critical").sum()
open_count = (filtered["status"] == "Open").sum()
resolved_count = (filtered["status"] == "Resolved").sum()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Findings", len(filtered))
c2.metric("Critical Findings", int(critical_count))
c3.metric("Open Findings", int(open_count))
c4.metric("Resolved Findings", int(resolved_count))

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Findings by Severity")
    severity_counts = (
        filtered["severity"]
        .value_counts()
        .reindex(severity_order, fill_value=0)
        .rename_axis("Severity")
        .reset_index(name="Count")
    )
    fig = px.bar(
        severity_counts,
        x="Severity",
        y="Count",
        color="Severity",
        category_orders={"Severity": severity_order},
        title="Severity Distribution",
    )
    st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Remediation Status")
    status_counts = (
        filtered["status"]
        .value_counts()
        .reindex(status_order, fill_value=0)
        .rename_axis("Status")
        .reset_index(name="Count")
    )
    fig = px.pie(
        status_counts,
        names="Status",
        values="Count",
        hole=0.45,
        title="Remediation Progress",
    )
    st.plotly_chart(fig, use_container_width=True)

st.subheader("Exposure Findings")

display_df = filtered.copy()
display_df["exposure_date"] = (
    display_df["exposure_date"].dt.strftime("%Y-%m-%d")
)
st.dataframe(display_df, use_container_width=True, hide_index=True)

st.caption(
    "Educational demonstration using synthetic records. "
    "No real passwords or exposed credentials are stored."
)

st.divider()
st.subheader("Update Remediation Status")

if not filtered.empty:
    finding_id = st.selectbox(
        "Select finding",
        filtered["finding_id"].tolist(),
    )

    current_status = filtered.loc[
        filtered["finding_id"] == finding_id, "status"
    ].iloc[0]

    new_status = st.selectbox(
        "New status",
        status_order,
        index=status_order.index(current_status),
    )

    if st.button("Save Status"):
        df.loc[df["finding_id"] == finding_id, "status"] = new_status
        df.to_csv(DATA_FILE, index=False)
        st.success(f"{finding_id} status updated to {new_status}.")
        st.rerun()
else:
    st.info("No findings match the selected filters.")
