"""
OpenCTI client for fetching threat intelligence indicators over GraphQL.

AiSOC — open-source AI Security Operations Center (MIT License)

Talks to an OpenCTI platform's /graphql endpoint with an admin/user API
token (Authorization: <token>, per OpenCTI's auth scheme — no Bearer prefix
is required by the platform, both forms are accepted here). Uses the
`stixCoreObjects` list query limited to indicator-type objects, paginated
with `first`/`after` cursors, incremental by `updated_since` when supplied.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

#: STIX indicator types OpenCTI returns mapped to the internal IOC vocabulary
#: used by pipeline.ingest_iocs (same vocabulary as the MISP client).
_STIX_TYPE_MAP: dict[str, str] = {
    "ipv4-addr": "ipv4",
    "ipv6-addr": "ipv6",
    "domain-name": "domain",
    "url": "url",
    "file": "sha256",  # resolved from hashes below when not sha256
    "email-addr": "email",
    "mac-address": "mac",
    "autonomous-system": "asn",
    "mutual-tls-fingerprint": "x509-fingerprint",
    "cryptocurrency-wallet": "cryptowallet",
    "text": "other",
}

#: Main GraphQL selection. Kept to fields present across OpenCTI 5.x/6.x.
_STIX_CORE_QUERY = """
query AiSOCIndicators($first: Int!, $after: String, $since: DateTime) {
  stixCoreObjects(
    types: ["Indicator"]
    first: $first
    after: $after
    orderBy: updated_at
    orderMode: asc
    filters: {
      key: "updated"
      values: [$since]
      operator: gt
      mode: and
    }
  ) {
    edges {
      cursor
      node {
        id
        standard_id
        type
        pattern
        pattern_type
        name
        description
        key
        value
        x_opencti_score
        x_opencti_main_observable_type
        confidence
        created
        modified
        revoked
        indicator_types
        KillChainPhases { edges { node { kill_chain_name phase_name } } }
        externalReferences { edges { node { source_name external_id url } } }
        labels
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


class OpenCtiClient:
    """Async OpenCTI GraphQL client.

    Fetches Indicator stix-core-objects incrementally and normalises them
    to the same IOC dict shape the MISP/TAXII handlers feed the pipeline.
    """

    def __init__(
        self,
        url: str,
        token: str,
        verify_ssl: bool = True,
        page_size: int = 500,
    ) -> None:
        # Accept a platform root or a full /graphql path.
        base = url.rstrip("/")
        self._graphql_url = base if base.endswith("/graphql") else f"{base}/graphql"
        self._verify_ssl = verify_ssl
        self._page_size = max(1, min(page_size, 1000))
        # OpenCTI accepts the raw token; send both forms for proxy tolerance.
        self._headers = {
            "Authorization": token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self._last_sync: datetime | None = None

    async def _graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(
            headers=self._headers, verify=self._verify_ssl, timeout=60.0
        ) as client:
            resp = await client.post(
                self._graphql_url, json={"query": query, "variables": variables}
            )
            resp.raise_for_status()
            body = resp.json()
            if "errors" in body:
                # GraphQL transport succeeded but the operation failed —
                # surface it rather than returning a silent empty list.
                raise RuntimeError(f"OpenCTI GraphQL errors: {body['errors'][:2]}")
            return body.get("data") or {}

    async def get_recent_indicators(
        self, since_hours: int = 24
    ) -> list[dict[str, Any]]:
        """Fetch Indicator objects updated within the last N hours (paginated)."""
        since = (
            self._last_sync
            or (datetime.now(UTC) - timedelta(hours=since_hours))
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        nodes: list[dict[str, Any]] = []
        after: str | None = None
        while True:
            data = await self._graphql(
                _STIX_CORE_QUERY,
                {"first": self._page_size, "after": after, "since": since},
            )
            block = data.get("stixCoreObjects") or {}
            for edge in block.get("edges") or []:
                node = edge.get("node") or {}
                if node.get("revoked"):
                    continue
                nodes.append(node)
            page_info = block.get("pageInfo") or {}
            if not page_info.get("hasNextPage") or not page_info.get("endCursor"):
                break
            after = page_info["endCursor"]

        self._last_sync = datetime.now(UTC)
        logger.info("OpenCTI indicators fetched", count=len(nodes), since=since)
        return nodes

    def extract_iocs(self, node: dict[str, Any]) -> list[dict[str, Any]]:
        """Normalise one OpenCTI Indicator node to pipeline IOC dicts.

        An indicator pattern like ``[ipv4-addr:value = '1.2.3.4']`` yields
        the observable value; multi-value patterns yield one IOC each.
        """
        pattern = str(node.get("pattern") or node.get("key") or "")
        ioc_type = _STIX_TYPE_MAP.get(
            str(node.get("x_opencti_main_observable_type") or "").lower(),
            _STIX_TYPE_MAP.get(str(node.get("pattern_type") or "").lower(), "other"),
        )

        values = _pattern_values(pattern)
        if not values:
            value = str(node.get("value") or "").strip()
            values = [value] if value else []

        kill_chain = [
            f"{p.get('kill_chain_name', '')}:{p.get('phase_name', '')}".strip(":")
            for p in (
                (e.get("node") or {})
                for e in ((node.get("KillChainPhases") or {}).get("edges") or [])
            )
        ]
        refs = [
            {"source": (r.get("node") or {}).get("source_name"),
             "url": (r.get("node") or {}).get("url")}
            for r in ((node.get("externalReferences") or {}).get("edges") or [])
        ]
        score = node.get("x_opencti_score")

        iocs: list[dict[str, Any]] = []
        for v in values:
            iocs.append({
                "type": ioc_type,
                "value": v,
                "category": (node.get("indicator_types") or ["unknown"])[0],
                "to_ids": True,
                "comment": str(node.get("description") or "")[:500],
                "tags": list(node.get("labels") or []) + kill_chain,
                "source": "opencti",
                "source_ref": f"opencti:{node.get('standard_id') or node.get('id', '')}",
                "event_info": str(node.get("name") or "")[:300],
                "confidence": node.get("confidence"),
                "score": score,
                "reliability": _score_to_confidence(score),
                "tlp": _extract_tlp(node.get("labels") or []),
                "external_references": refs,
                "last_modified": node.get("modified"),
            })
        return iocs


def _pattern_values(pattern: str) -> list[str]:
    """Extract quoted literal values from a STIX comparison expression.

    ``[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8']``
    → ``['1.2.3.4', '5.6.7.8']``. Regex over the pattern text is the
    standard trick; OpenCTI patterns are deliberately simple grammar.
    """
    import re

    return [m for m in re.findall(r"'([^']+)'", pattern) if m]


def _extract_tlp(labels: list[Any]) -> str:
    for label in labels:
        name = str(label).lower()
        if name.startswith("tlp:") or name.startswith("lp:"):
            return name.split(":", 1)[-1]
    return "white"


def _score_to_confidence(score: Any) -> str:
    """Map OpenCTI's 0-100 confidence score to the A-F reliability scale
    the enrichment layer understands (same mapping as OTX's pulses)."""
    try:
        s = int(score)
    except (TypeError, ValueError):
        return "C"
    if s >= 90:
        return "A"
    if s >= 75:
        return "B"
    if s >= 50:
        return "C"
    if s >= 25:
        return "D"
    return "E"
