"""Process-wide runtime metrics shared by main.py and the system router."""
from typing import Any, Dict

metrics: Dict[str, Any] = {
    "start_time": None,
    "requests_total": 0,
    "requests_errors": 0,
    "last_correlation_sweep": None,
    "last_correlation_findings": 0,
    "last_intel_refresh": None,
    "last_retention_run": None,
    "last_incident_lifecycle_run": None,
}
