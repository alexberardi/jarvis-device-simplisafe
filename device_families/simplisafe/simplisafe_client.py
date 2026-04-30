"""Lightweight SimpliSafe REST client using httpx.

Handles OAuth2 token refresh and all SimpliSafe V3 API calls.
Only depends on httpx (already in node requirements) and Python stdlib.

SimpliSafe has no official public API — this uses the same endpoints as
the mobile app.  Auth uses Auth0 with PKCE; after the one-time browser
login the refresh token is stored and rotated automatically.
"""

from __future__ import annotations

import base64
import hashlib
import os
import urllib.parse
import uuid
from dataclasses import dataclass
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Auth0 / SimpliSafe constants (same values the mobile app uses)
# ---------------------------------------------------------------------------

AUTH0_DOMAIN = "auth.simplisafe.com"
CLIENT_ID = "42aBZ5lYrVW12jfOuu3CQROitwxg9sN5"
REDIRECT_URI = (
    "com.simplisafe.mobile://auth.simplisafe.com"
    "/ios/com.simplisafe.mobile/callback"
)
AUDIENCE = "https://api.simplisafe.com/"
SCOPE = "offline_access email openid https://api.simplisafe.com/scopes/user:platform"
TOKEN_URL = f"https://{AUTH0_DOMAIN}/oauth/token"
AUTHORIZE_URL = f"https://{AUTH0_DOMAIN}/authorize"
API_BASE = "https://api.simplisafe.com/v1"
_TIMEOUT = 30

# Auth0 client metadata (matches the iOS mobile app)
_AUTH0_CLIENT = base64.b64encode(
    b'{"version":"2.3.2","name":"Auth0.swift","env":{"swift":"5.x","iOS":"16.3"}}'
).decode("ascii")

_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15"
)

_AUTH_HEADERS: dict[str, str] = {
    "Host": AUTH0_DOMAIN,
    "Content-Type": "application/json",
    "Auth0-Client": _AUTH0_CLIENT,
}

_API_HEADERS: dict[str, str] = {
    "Host": "api.simplisafe.com",
    "Content-Type": "application/json; charset=utf-8",
    "User-Agent": _USER_AGENT,
}

# Sensor type IDs (from SimpliSafe V3 API)
SENSOR_TYPES: dict[int, str] = {
    0: "remote",
    1: "keypad",
    2: "keychain",
    3: "panic_button",
    4: "motion",
    5: "entry",
    6: "glass_break",
    7: "carbon_monoxide",
    8: "smoke",
    9: "leak",
    10: "temperature",
    12: "camera",
    13: "siren",
    14: "smoke_co",
    15: "doorbell",
    16: "lock",
    17: "outdoor_camera",
    20: "motion_v2",
}


# ---------------------------------------------------------------------------
# PKCE helpers (for the one-time authorize script)
# ---------------------------------------------------------------------------


def generate_code_verifier() -> str:
    """Generate a random PKCE code verifier."""
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")


def generate_code_challenge(verifier: str) -> str:
    """SHA-256 hash of the verifier, base64url-encoded."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_authorize_url(code_challenge: str) -> str:
    """Build the Auth0 authorize URL for browser-based login."""
    params = {
        "audience": AUDIENCE,
        "client_id": CLIENT_ID,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPE,
        "auth0Client": _AUTH0_CLIENT,
        "device": "iPhone",
        "device_id": str(uuid.uuid4()).upper(),
    }
    return f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"


def exchange_authorization_code(
    authorization_code: str, code_verifier: str,
) -> dict[str, Any]:
    """Exchange an authorization code + PKCE verifier for tokens.

    Returns the raw token response dict containing at minimum
    ``access_token`` and ``refresh_token``.
    """
    resp = httpx.post(
        TOKEN_URL,
        headers=_AUTH_HEADERS,
        json={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": authorization_code,
            "code_verifier": code_verifier,
            "redirect_uri": REDIRECT_URI,
        },
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SimpliSafeSystem:
    """A SimpliSafe alarm system (subscription)."""

    subscription_id: int
    name: str
    alarm_state: str  # OFF, HOME, AWAY, ALARM, etc.
    is_alarming: bool
    serial: str
    version: int  # 2 or 3
    address: str


@dataclass
class SimpliSafeSensor:
    """A sensor attached to a SimpliSafe system."""

    serial: str
    name: str
    sensor_type: int
    sensor_type_name: str
    triggered: bool
    offline: bool
    low_battery: bool
    temperature: int | None = None
    error: bool = False


@dataclass
class SimpliSafeLock:
    """A SimpliSafe smart lock."""

    serial: str
    name: str
    state: str  # locked, unlocked, jammed, unknown
    disabled: bool
    low_battery: bool
    pin_pad_low_battery: bool = False
    pin_pad_offline: bool = False


# ---------------------------------------------------------------------------
# REST client
# ---------------------------------------------------------------------------


class SimpliSafeClient:
    """Thin REST wrapper around the SimpliSafe cloud API.

    Authenticates with a refresh token (obtained via one-time browser
    login).  SimpliSafe refresh tokens are **single-use** — each refresh
    produces a new token.  The caller must persist ``new_refresh_token``
    after each ``authenticate()`` call.
    """

    def __init__(self, refresh_token: str) -> None:
        self._refresh_token: str = refresh_token
        self._access_token: str | None = None
        self._user_id: str | None = None
        self.new_refresh_token: str | None = None

    def authenticate(self) -> None:
        """Exchange refresh token for a new access token.

        After calling this, check ``new_refresh_token`` — if set, persist
        it (the old one is now invalid).
        """
        resp = httpx.post(
            TOKEN_URL,
            headers=_AUTH_HEADERS,
            json={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": self._refresh_token,
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        self._access_token = data["access_token"]
        if "refresh_token" in data:
            self.new_refresh_token = data["refresh_token"]

        # Resolve user ID
        auth_resp = self._request("GET", "api/authCheck")
        self._user_id = str(auth_resp.json()["userId"])

    # -- API methods ----------------------------------------------------------

    def get_systems(self) -> list[SimpliSafeSystem]:
        """List all alarm systems on the account."""
        resp = self._request(
            "GET",
            f"users/{self._user_id}/subscriptions",
            params={"activeOnly": "true"},
        )
        systems: list[SimpliSafeSystem] = []
        for sub in resp.json().get("subscriptions", []):
            sys_info = sub.get("system", {})
            location = sub.get("location", {})
            address_parts = [
                location.get("street1", ""),
                location.get("city", ""),
                location.get("state", ""),
            ]
            address = ", ".join(p for p in address_parts if p)
            systems.append(
                SimpliSafeSystem(
                    subscription_id=sub["sid"],
                    name=address or f"System {sub['sid']}",
                    alarm_state=sys_info.get("alarmState", "UNKNOWN").upper(),
                    is_alarming=sys_info.get("isAlarming", False),
                    serial=sys_info.get("serial", ""),
                    version=sys_info.get("version", 3),
                    address=address,
                )
            )
        return systems

    def get_sensors(self, subscription_id: int) -> list[SimpliSafeSensor]:
        """List all sensors for a system."""
        resp = self._request(
            "GET", f"ss3/subscriptions/{subscription_id}/sensors",
        )
        sensors: list[SimpliSafeSensor] = []
        for s in resp.json().get("sensors", []):
            sensor_type = s.get("type", 99)
            status = s.get("status", {})
            temp_info = status.get("temperature")
            temperature: int | None = None
            if isinstance(temp_info, dict):
                temperature = temp_info.get("value")
            elif isinstance(temp_info, (int, float)):
                temperature = int(temp_info)

            sensors.append(
                SimpliSafeSensor(
                    serial=s.get("serial", ""),
                    name=s.get("name", "Unknown Sensor"),
                    sensor_type=sensor_type,
                    sensor_type_name=SENSOR_TYPES.get(sensor_type, "unknown"),
                    triggered=status.get("triggered", False),
                    offline=status.get("offline", False),
                    low_battery=status.get("lowBattery", False),
                    temperature=temperature,
                    error=status.get("malfunction", False),
                )
            )
        return sensors

    def get_locks(self, subscription_id: int) -> list[SimpliSafeLock]:
        """List all locks for a system."""
        resp = self._request("GET", f"doorlock/{subscription_id}")
        locks: list[SimpliSafeLock] = []
        for lock_data in resp.json():
            state_val = lock_data.get("status", {}).get("lockState", 0)
            state_map = {0: "unknown", 1: "locked", 2: "unlocked", 3: "jammed"}
            locks.append(
                SimpliSafeLock(
                    serial=lock_data.get("serial", ""),
                    name=lock_data.get("name", "SimpliSafe Lock"),
                    state=state_map.get(state_val, "unknown"),
                    disabled=lock_data.get("status", {}).get("disabled", False),
                    low_battery=lock_data.get("status", {}).get(
                        "lockLowBattery", False,
                    ),
                    pin_pad_low_battery=lock_data.get("status", {}).get(
                        "pinPadLowBattery", False,
                    ),
                    pin_pad_offline=lock_data.get("status", {}).get(
                        "pinPadOffline", False,
                    ),
                )
            )
        return locks

    def set_system_state(
        self, subscription_id: int, state: str, version: int = 3,
    ) -> None:
        """Arm or disarm the system.

        Args:
            subscription_id: The system subscription ID.
            state: One of "off", "home", "away".
            version: System version (2 or 3). V2 uses a different endpoint.
        """
        if version >= 3:
            self._request(
                "POST",
                f"ss3/subscriptions/{subscription_id}/state/{state}",
            )
        else:
            self._request(
                "POST",
                f"subscriptions/{subscription_id}/state",
                json={"state": state},
            )

    def set_lock_state(
        self, subscription_id: int, serial: str, state: str,
    ) -> None:
        """Lock or unlock a door lock.

        Args:
            subscription_id: The system subscription ID.
            serial: The lock's serial number.
            state: "lock" or "unlock".
        """
        self._request(
            "POST",
            f"doorlock/{subscription_id}/{serial}/state",
            json={"state": state},
        )

    # -- internal -------------------------------------------------------------

    def _request(
        self, method: str, path: str, **kwargs: Any,
    ) -> httpx.Response:
        url = f"{API_BASE}/{path}"
        headers = {
            **_API_HEADERS,
            "Authorization": f"Bearer {self._access_token or ''}",
        }
        resp = httpx.request(
            method, url, headers=headers, timeout=_TIMEOUT, **kwargs,
        )
        resp.raise_for_status()
        return resp
