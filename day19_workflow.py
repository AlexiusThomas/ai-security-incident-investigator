
"""Day 19: Automated security investigation and reporting."""

import json
from pathlib import Path

from integrated_pipeline import run_pipeline
from investigate import create_investigation
from report_incident import build_report


def complete_workflow(
    url,
    output_dir="day19_output",
    rules_file=None
):
    """Run ingestion through incident reporting."""

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    # Step 1: Ingestion, normalization, detection, correlation
    summary = run_pipeline(
        url,
        output_dir=output,
        rules_file=rules_file
    )

    # Step 2: Load correlated incidents
    incidents_path = output / "incidents.json"

    with incidents_path.open(encoding="utf-8") as file:
        incidents = json.load(file)

    if not isinstance(incidents, list):
        raise ValueError("Incidents must be a list")

    # Step 3: Create investigations
    investigations = [
        create_investigation(incident, index)
        for index, incident in enumerate(incidents, 1)
    ]

    investigations_path = output / "investigations.json"

    with investigations_path.open("w", encoding="utf-8") as file:
        json.dump(investigations, file, indent=2)

    # Step 4: Generate Markdown reports
    reports_dir = output / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    for investigation in investigations:
        investigation_id = investigation["investigation_id"]

        report = build_report(investigation)

        report_path = reports_dir / f"{investigation_id}.md"
        report_path.write_text(report, encoding="utf-8")

    # Step 5: Return workflow statistics
    return {
        **summary,
        "investigations": len(investigations),
        "reports": len(investigations),
        "output_directory": str(output)
    }
