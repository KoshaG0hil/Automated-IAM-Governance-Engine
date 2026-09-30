"""Report Generator: Outputs audit-ready reports in JSON, CSV, and interactive HTML formats."""

import csv
from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates structured audit reports across multiple formats."""

    def __init__(self, templates_dir: str = "src/reporting/templates"):
        self.templates_dir = templates_dir
        if os.path.exists(templates_dir):
            self.jinja_env = Environment(loader=FileSystemLoader(templates_dir))
        else:
            self.jinja_env = None

    def export_json(self, data: Dict[str, Any], output_path: str):
        """Export raw findings and metrics to JSON."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"Saved JSON audit report to {output_path}")

    def export_csv(self, findings: list, output_path: str):
        """Export findings to CSV for compliance spreadsheets."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        fields = [
            "severity",
            "priority",
            "adjusted_risk_score",
            "category",
            "resource_type",
            "resource_name",
            "resource_arn",
            "title",
            "description",
            "remediation"
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for finding in findings:
                writer.writerow(finding)
        logger.info(f"Saved CSV audit report to {output_path}")

    def export_html(self, summary_data: Dict[str, Any], account_id: str, output_path: str):
        """Render interactive HTML dashboard using Jinja2."""
        if not self.jinja_env:
            logger.error("Jinja environment not initialized; cannot render HTML.")
            return

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        template = self.jinja_env.get_template("report.html")
        html_out = template.render(
            account_id=account_id,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            summary=summary_data
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_out)
        logger.info(f"Saved HTML audit report to {output_path}")

    def generate_all(self, summary_data: Dict[str, Any], account_id: str, output_dir: str = "reports") -> Dict[str, str]:
        """Generate JSON, CSV, and HTML reports in one step."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        json_file = os.path.join(output_dir, f"iam_audit_{timestamp_slug}.json")
        csv_file = os.path.join(output_dir, f"iam_audit_{timestamp_slug}.csv")
        html_file = os.path.join(output_dir, f"iam_audit_{timestamp_slug}.html")

        # Also create symbolic / static latest copies for easy viewing
        latest_html = os.path.join(output_dir, "latest_audit_report.html")

        self.export_json(summary_data, json_file)
        self.export_csv(summary_data.get("findings", []), csv_file)
        self.export_html(summary_data, account_id, html_file)
        self.export_html(summary_data, account_id, latest_html)

        return {
            "json": json_file,
            "csv": csv_file,
            "html": html_file,
            "latest_html": latest_html
        }
