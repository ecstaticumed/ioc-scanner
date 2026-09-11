import json
from datetime import datetime, timezone
from pathlib import Path


class IOCScanner:

    def __init__(self, database_path):
        self.database_path = Path(database_path)
        self.database = self._load_database()

    def _load_database(self):
        """Load IOC data from the JSON database."""

        if not self.database_path.exists():
            raise FileNotFoundError(
                f"IOC database not found: {self.database_path}"
            )

        with open(self.database_path, "r", encoding="utf-8") as file:
            return json.load(file)

    def _get_iocs_for_type(self, ioc_type):
        """Return IOCs matching the requested type."""

        if ioc_type in ("md5", "sha1", "sha256"):
            return self.database.get("hashes", [])

        return self.database.get(f"{ioc_type}s", [])

    def scan(self, ioc, ioc_type):
        """Scan an IOC against the local database."""

        ioc = ioc.strip().lower()

        known_iocs = [
            item.lower()
            for item in self._get_iocs_for_type(ioc_type)
        ]

        found = ioc in known_iocs

        if found:
            status = "MATCH"
            risk = "HIGH"
        else:
            status = "NO_MATCH"
            risk = "UNKNOWN"

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ioc": ioc,
            "type": ioc_type,
            "status": status,
            "risk": risk
        }
