"""
netlab.dns.cache — a TTL-respecting DNS cache.

Caching is what makes DNS survive its own load. Without it every page view
would re-query the root servers, and the hierarchy would collapse under the
traffic. The TTL on every record is the authority's instruction for how long
the answer may be reused.

    put("example.com", A, ["93.184.216.34"], ttl=300)
        → usable for 300 seconds, then it must be fetched again

Honouring TTL is not optional politeness: it is how an operator moves a
service. They lower the TTL, wait for the old one to expire everywhere, change
the record, and traffic follows. A resolver that ignores TTL keeps sending
users to a decommissioned address.

Negative caching (RFC 2308) is not implemented here, and that is a deliberate
omission worth naming: a real resolver also caches NXDOMAIN, using the SOA
minimum field as the TTL, so that a typo'd domain does not hammer the
authority on every retry.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class CacheEntry:
    name: str
    qtype: int
    addresses: list[str]
    ttl: int
    stored_at: float = field(default_factory=time.monotonic)

    def age(self) -> float:
        return time.monotonic() - self.stored_at

    def remaining_ttl(self) -> int:
        return max(0, int(self.ttl - self.age()))

    def is_expired(self) -> bool:
        return self.age() >= self.ttl


class DnsCache:
    """
    Keyed on (name, qtype), evicting on TTL expiry and on capacity.

    Thread-safe, because the GUI reads the statistics from the Qt thread while
    the resolver writes from a worker.
    """

    def __init__(self, capacity: int = 256) -> None:
        self.capacity = capacity
        self._entries: dict[tuple[str, int], CacheEntry] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        self.expirations = 0
        self.evictions = 0

    def get(self, name: str, qtype: int) -> CacheEntry | None:
        key = (name.lower().rstrip("."), qtype)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self.misses += 1
                return None
            if entry.is_expired():
                # Expiry is a miss, not a hit: the answer existed but is no
                # longer usable, which is the whole point of the TTL.
                del self._entries[key]
                self.expirations += 1
                self.misses += 1
                return None
            self.hits += 1
            return entry

    def put(self, name: str, qtype: int, addresses: list[str], ttl: int) -> None:
        if ttl <= 0:
            return   # TTL 0 means "use once, do not store"
        key = (name.lower().rstrip("."), qtype)
        with self._lock:
            if len(self._entries) >= self.capacity and key not in self._entries:
                oldest = min(self._entries.items(),
                             key=lambda item: item[1].stored_at)[0]
                del self._entries[oldest]
                self.evictions += 1
            self._entries[key] = CacheEntry(name, qtype, list(addresses), ttl)

    def purge_expired(self) -> int:
        with self._lock:
            expired = [k for k, v in self._entries.items() if v.is_expired()]
            for key in expired:
                del self._entries[key]
            self.expirations += len(expired)
            return len(expired)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def entries(self) -> list[CacheEntry]:
        with self._lock:
            return sorted(self._entries.values(), key=lambda e: e.name)

    def stats(self) -> dict:
        with self._lock:
            total = self.hits + self.misses
            return {
                "size": len(self._entries),
                "capacity": self.capacity,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(self.hits / total, 3) if total else 0.0,
                "expirations": self.expirations,
                "evictions": self.evictions,
            }

    def __len__(self) -> int:
        return len(self._entries)
