from typing import Dict, Any

class ReportGenerator:
    def __init__(self, format: str = "json"):
        self.format = format

    def generate(self, analysis_results: Dict[str, Any]) -> str:
        """Generates a report based on the analysis results."""
        if self.format == "json":
            return self._generate_json(analysis_results)
        else:
            raise ValueError(f"Unsupported report format: {self.format}")

    def _generate_json(self, results: Dict[str, Any]) -> str:
        import json
        return json.dumps(results, indent=4)
