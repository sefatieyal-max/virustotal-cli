"""Record of one lookup in this session."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class HistoryEntry:
    """One lookup: what was checked, the verdict, and when."""

    kind: str
    indicator: str
    verdict: str
    from_cache: bool = False
    checked_at: datetime = field(default_factory=datetime.now)