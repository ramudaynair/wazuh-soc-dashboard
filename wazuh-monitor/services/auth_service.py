"""
auth_service.py — Wazuh JWT authentication with automatic token refresh.

The browser NEVER sees the JWT or Wazuh credentials.
Tokens are stored in memory only.
"""

import time
import logging
import requests
import urllib3

# Suppress InsecureRequestWarning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("wazuh-monitor.auth")


class AuthService:
    """Manages Wazuh API authentication lifecycle."""

    # Wazuh default JWT lifetime is 900 s; refresh 120 s early.
    TOKEN_REFRESH_MARGIN = 120

    def __init__(self):
        self._api_url = ""
        self._username = ""
        self._password = ""
        self._verify_ssl = False
        self._token = None
        self._token_expires = 0       # epoch seconds
        self._connected = False
        self._last_error = None

    # ── Configuration ───────────────────────────────────────────

    def configure(self, api_url, username, password, verify_ssl=False):
        """Set credentials.  Does NOT authenticate yet."""
        self._api_url = api_url.rstrip("/")
        self._username = username
        self._password = password
        self._verify_ssl = verify_ssl
        self._token = None
        self._token_expires = 0
        self._connected = False
        self._last_error = None

    # ── Public helpers ──────────────────────────────────────────

    @property
    def api_url(self):
        return self._api_url

    @property
    def is_configured(self):
        return bool(self._api_url and self._username and self._password)

    @property
    def is_connected(self):
        return self._connected and self._token is not None

    @property
    def last_error(self):
        return self._last_error

    # ── Authenticate ────────────────────────────────────────────

    def authenticate(self):
        """
        Obtain a JWT from the Wazuh API.

        Wazuh 4.x endpoint:
            GET /security/user/authenticate?raw=true
            Authorization: Basic <base64>
        Returns the raw JWT string.
        """
        if not self.is_configured:
            self._last_error = "Credentials not configured"
            return False

        url = f"{self._api_url}/security/user/authenticate?raw=true"
        log.info("Authenticating with %s as %s", self._api_url, self._username)

        try:
            resp = requests.get(
                url,
                auth=(self._username, self._password),
                verify=self._verify_ssl,
                timeout=15,
            )

            if resp.status_code == 200:
                token = resp.text.strip().strip('"').strip("'")
                if token and len(token) > 20:
                    self._token = token
                    # Wazuh default token lifetime = 900 s
                    self._token_expires = time.time() + 900
                    self._connected = True
                    self._last_error = None
                    log.info("Authentication successful (token %s…)", token[:20])
                    return True
                else:
                    self._last_error = "Received empty or invalid token"
                    log.error(self._last_error)
                    return False
            else:
                self._last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                log.error("Auth failed: %s", self._last_error)
                self._connected = False
                return False

        except requests.exceptions.ConnectionError as exc:
            self._last_error = f"Connection refused: {exc}"
            log.error(self._last_error)
            self._connected = False
            return False
        except requests.exceptions.Timeout:
            self._last_error = "Connection timed out (15 s)"
            log.error(self._last_error)
            self._connected = False
            return False
        except Exception as exc:
            self._last_error = f"Unexpected error: {exc}"
            log.exception(self._last_error)
            self._connected = False
            return False

    # ── Token access (auto-refresh) ─────────────────────────────

    def get_token(self):
        """
        Return a valid JWT string, refreshing automatically if close to expiry.
        Returns None if not authenticated.
        """
        if not self._token:
            return None

        # Refresh if within the margin
        if time.time() > (self._token_expires - self.TOKEN_REFRESH_MARGIN):
            log.info("Token nearing expiry — refreshing")
            if not self.authenticate():
                log.warning("Token refresh failed; using stale token")

        return self._token

    def get_headers(self):
        """Return dict with Authorization header, or empty dict if no token."""
        token = self.get_token()
        if not token:
            return {}
        return {"Authorization": f"Bearer {token}"}

    # ── Disconnect ──────────────────────────────────────────────

    def disconnect(self):
        """Clear token and mark as disconnected."""
        self._token = None
        self._token_expires = 0
        self._connected = False
        self._last_error = None

    # ── Status summary ──────────────────────────────────────────

    def status(self):
        """Return a JSON-serialisable status dict (no secrets)."""
        return {
            "connected": self._connected,
            "api_url": self._api_url,
            "username": self._username,
            "has_token": self._token is not None,
            "token_expires_in": max(0, int(self._token_expires - time.time())),
            "last_error": self._last_error,
        }


# Module-level singleton
auth = AuthService()
