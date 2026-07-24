"""Report generation module."""
from typing import Any
from netzilla.interfaces import AnalysisResult, Reporter


class ReportGenerator(Reporter):
    """Generates reports in various formats."""

    def __init__(self, fmt: str = "json"):
        self.fmt = fmt

    def generate(self, result: AnalysisResult) -> str:
        """Generates a report based on the analysis results."""
        if self.fmt == "json":
            return self.to_json(result)
        # Support dict format as string if json is not requested
        return str(self.to_dict(result))

    def to_json(self, result: AnalysisResult) -> str:
        """Export as JSON."""
        return result.model_dump_json(indent=4)

    def to_dict(self, result: AnalysisResult) -> dict[str, Any]:
        """Export as dictionary."""
        return result.model_dump()
