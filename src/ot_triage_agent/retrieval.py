"""Small, transparent local retrieval layer for synthetic OT runbooks."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

from .models import Alert, Evidence, RunbookEntry

TOKEN_PATTERN = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{1,}")
STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "the",
    "to",
    "with",
}


def tokenize(text: str) -> list[str]:
    return [
        token.lower().replace("-", "_")
        for token in TOKEN_PATTERN.findall(text)
        if token.lower() not in STOPWORDS
    ]


class RunbookIndex:
    """In-memory TF-IDF index; no cloud service or embedding model required."""

    def __init__(self, entries: list[RunbookEntry]) -> None:
        if not entries:
            raise ValueError("At least one runbook entry is required")
        self.entries = entries
        self._documents = [Counter(tokenize(entry.retrieval_text())) for entry in entries]
        self._idf = self._build_idf(self._documents)

    @classmethod
    def from_json(cls, path: str | Path) -> RunbookIndex:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("Runbook file must contain a JSON list")
        return cls([RunbookEntry.from_dict(item) for item in payload])

    @staticmethod
    def _build_idf(documents: list[Counter[str]]) -> dict[str, float]:
        document_count = len(documents)
        frequencies: Counter[str] = Counter()
        for document in documents:
            frequencies.update(document.keys())
        return {
            token: math.log((1 + document_count) / (1 + frequency)) + 1
            for token, frequency in frequencies.items()
        }

    def _vector(self, tokens: list[str] | Counter[str]) -> dict[str, float]:
        counts = tokens if isinstance(tokens, Counter) else Counter(tokens)
        return {
            token: count * self._idf.get(token, 1.0)
            for token, count in counts.items()
        }

    @staticmethod
    def _cosine(left: dict[str, float], right: dict[str, float]) -> float:
        shared = left.keys() & right.keys()
        numerator = sum(left[token] * right[token] for token in shared)
        left_norm = math.sqrt(sum(value * value for value in left.values()))
        right_norm = math.sqrt(sum(value * value for value in right.values()))
        if not left_norm or not right_norm:
            return 0.0
        return numerator / (left_norm * right_norm)

    def retrieve(self, query: str, top_k: int = 3) -> list[tuple[RunbookEntry, Evidence]]:
        if top_k < 1:
            return []
        query_vector = self._vector(tokenize(query))
        normalized_query = query.lower()
        ranked: list[tuple[float, RunbookEntry]] = []
        for entry, document in zip(self.entries, self._documents, strict=True):
            score = self._cosine(query_vector, self._vector(document))
            # Preserve strong routing signals such as asset_offline and
            # degraded_network instead of letting generic terms dominate.
            if any("_" in tag and tag in normalized_query for tag in entry.tags):
                score = min(score + 0.20, 1.0)
            ranked.append((score, entry))
        ranked.sort(key=lambda item: (-item[0], item[1].runbook_id))

        results: list[tuple[RunbookEntry, Evidence]] = []
        for score, entry in ranked[: min(top_k, len(ranked))]:
            evidence = Evidence(
                runbook_id=entry.runbook_id,
                title=entry.title,
                relevance=round(score, 3),
                excerpt=entry.summary[:320],
            )
            results.append((entry, evidence))
        return results


def load_alerts(path: str | Path) -> list[Alert]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Alert file must contain a JSON list")
    return [Alert.from_dict(item) for item in payload]
