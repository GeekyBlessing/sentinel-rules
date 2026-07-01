"""Loads and parses Sigma-format detection rules from the rules/ directory."""
import yaml
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class SigmaRule:
    id: str
    title: str
    description: str
    level: str
    status: str
    tags: list
    detection: dict
    timeframe: str = None
    falsepositives: list = field(default_factory=list)
    raw_path: str = ""

    @property
    def mitre_techniques(self):
        return [t.replace("attack.t", "T").upper() for t in self.tags if t.startswith("attack.t")]

    @property
    def mitre_tactics(self):
        return [t.replace("attack.", "").replace("-", " ").title()
                for t in self.tags if t.startswith("attack.") and not t.startswith("attack.t")]


def load_rules(rules_dir: str = "rules") -> list[SigmaRule]:
    rules = []
    for path in sorted(Path(rules_dir).glob("*.yml")):
        with open(path) as f:
            data = yaml.safe_load(f)
        rules.append(SigmaRule(
            id=data["id"],
            title=data["title"],
            description=data.get("description", "").strip(),
            level=data.get("level", "medium"),
            status=data.get("status", "experimental"),
            tags=data.get("tags", []),
            detection=data["detection"],
            timeframe=data.get("timeframe"),
            falsepositives=data.get("falsepositives", []),
            raw_path=str(path),
        ))
    return rules
