"""
cache_service.py — Thread-safe TTL-based in-memory cache.

Prevents excessive Wazuh API calls on rapid page loads.
Default TTL: 30 seconds.
"""

import time
import threading


class CacheService:
    """Simple key→value store where each entry expires after *ttl* seconds."""

    def __init__(self, default_ttl=30):
        self._store = {}          # key → (value, expires_at)
        self._lock = threading.Lock()
        self.default_ttl = default_ttl

    # ── Public API ──────────────────────────────────────────────

    def get(self, key):
        """Return cached value or None if missing / expired."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.time() > expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key, value, ttl=None):
        """Store *value* under *key* for *ttl* seconds (default: self.default_ttl)."""
        if ttl is None:
            ttl = self.default_ttl
        with self._lock:
            self._store[key] = (value, time.time() + ttl)

    def delete(self, key):
        """Remove a single key."""
        with self._lock:
            self._store.pop(key, None)

    def clear(self):
        """Flush every entry."""
        with self._lock:
            self._store.clear()

    def stats(self):
        """Return dict with cache diagnostics."""
        with self._lock:
            now = time.time()
            total = len(self._store)
            alive = sum(1 for _, (__, exp) in self._store.items() if exp > now)
            return {"total_keys": total, "alive_keys": alive}


# Module-level singleton so every service shares the same cache.
cache = CacheService(default_ttl=30)
