"""SimpliSafe home security protocol adapter (cloud)."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from jarvis_command_sdk import (
    DeviceControlResult,
    DiscoveredDevice,
    IJarvisButton,
    IJarvisDeviceProtocol,
    IJarvisSecret,
    JarvisSecret,
    JarvisStorage,
)
from jarvis_command_sdk.authentication import AuthenticationConfig

try:
    from jarvis_log_client import JarvisLogger
except ImportError:
    import logging

    class JarvisLogger:  # type: ignore[no-redef]
        def __init__(self, **kw: Any) -> None:
            self._log = logging.getLogger(kw.get("service", __name__))

        def info(self, msg: str, **kw: Any) -> None:
            self._log.info(msg)

        def warning(self, msg: str, **kw: Any) -> None:
            self._log.warning(msg)

        def error(self, msg: str, **kw: Any) -> None:
            self._log.error(msg)

        def debug(self, msg: str, **kw: Any) -> None:
            self._log.debug(msg)


from simplisafe_shared.simplisafe_client import (
    AUDIENCE,
    AUTHORIZE_URL,
    CLIENT_ID,
    REDIRECT_URI,
    SCOPE,
    TOKEN_URL,
    SimpliSafeClient,
)

logger = JarvisLogger(service="device.simplisafe")

_storage = JarvisStorage("simplisafe")

# Cache: avoid re-authenticating on every call within a single session
_cached_client: SimpliSafeClient | None = None


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _get_refresh_token() -> str | None:
    return _storage.get_secret("SIMPLISAFE_REFRESH_TOKEN", scope="integration")


def _save_refresh_token(token: str) -> None:
    _storage.set_secret("SIMPLISAFE_REFRESH_TOKEN", token, scope="integration")


def _build_client() -> SimpliSafeClient:
    """Authenticate and return a SimpliSafeClient, rotating the refresh token."""
    global _cached_client

    if _cached_client is not None:
        return _cached_client

    refresh_token = _get_refresh_token()
    if not refresh_token:
        raise ValueError(
            "SIMPLISAFE_REFRESH_TOKEN not configured — "
            "run the OAuth setup first"
        )

    client = SimpliSafeClient(refresh_token)
    client.authenticate()

    # SimpliSafe tokens are single-use — persist the new one
    if client.new_refresh_token:
        _save_refresh_token(client.new_refresh_token)
        logger.debug("Rotated SimpliSafe refresh token")

    _cached_client = client
    return client


def _invalidate_client() -> None:
    """Clear the cached client (e.g. on auth failure)."""
    global _cached_client
    _cached_client = None


class SimpliSafeProtocol(IJarvisDeviceProtocol):
    """SimpliSafe home security protocol adapter."""

    protocol_name: str = "simplisafe"
    friendly_name: str = "SimpliSafe"
    supported_domains: list[str] = ["security_system", "lock", "sensor"]
    connection_type: str = "cloud"
    setup_guide: str = """## SimpliSafe Setup

This integration connects to your SimpliSafe account via the same API
the mobile app uses.

### First-time setup

SimpliSafe requires a one-time browser login with MFA:

1. Run `python scripts/authorize.py` from the jarvis-device-simplisafe directory
2. Open the printed URL in your browser
3. Log in with your SimpliSafe credentials and complete MFA
4. Copy the authorization code from the redirect URL
5. Paste it back into the script

The script stores your refresh token securely on the node.

### What you can do

- **Arm / disarm** your security system (home, away, off)
- **Check sensor status** (doors, motion, glass break, etc.)
- **Lock / unlock** SimpliSafe smart locks

### Notes

- SimpliSafe has **no official public API** — this uses the same
  endpoints as the mobile app
- Refresh tokens are single-use and rotated automatically
- Avoid polling more than once per 30 seconds to prevent rate limiting"""

    @property
    def authentication(self) -> AuthenticationConfig:
        return AuthenticationConfig(
            type="oauth",
            provider="simplisafe",
            friendly_name="SimpliSafe",
            client_id=CLIENT_ID,
            keys=["refresh_token"],
            authorize_url=AUTHORIZE_URL,
            exchange_url=TOKEN_URL,
            scopes=SCOPE.split(),
            supports_pkce=True,
            native_redirect_uri=REDIRECT_URI,
            extra_authorize_params={"audience": AUDIENCE},
            refresh_token_secret_key="SIMPLISAFE_REFRESH_TOKEN",
            requires_background_refresh=True,
            refresh_interval_seconds=3000,  # ~50 min (tokens expire in 60)
        )

    @property
    def required_secrets(self) -> list[IJarvisSecret]:
        return [
            JarvisSecret(
                "SIMPLISAFE_REFRESH_TOKEN",
                "OAuth refresh token (obtained via browser login + MFA)",
                "integration",
                "string",
                is_sensitive=True,
                required=True,
                friendly_name="Refresh Token",
            ),
        ]

    @property
    def supported_actions(self) -> list[IJarvisButton]:
        return [
            IJarvisButton(
                button_text="Arm Home",
                button_action="arm_home",
                button_type="primary",
                button_icon="shield-home",
            ),
            IJarvisButton(
                button_text="Arm Away",
                button_action="arm_away",
                button_type="primary",
                button_icon="shield-lock",
            ),
            IJarvisButton(
                button_text="Disarm",
                button_action="disarm",
                button_type="secondary",
                button_icon="shield-off",
            ),
            IJarvisButton(
                button_text="Lock",
                button_action="lock",
                button_type="primary",
                button_icon="lock",
            ),
            IJarvisButton(
                button_text="Unlock",
                button_action="unlock",
                button_type="secondary",
                button_icon="lock-open",
            ),
        ]

    def store_auth_values(self, values: dict[str, str]) -> None:
        """Persist tokens received from the mobile OAuth flow."""
        if "refresh_token" in values:
            _save_refresh_token(values["refresh_token"])
            _invalidate_client()
            logger.info("SimpliSafe refresh token saved via OAuth flow")

    async def discover(self, timeout: float = 10.0) -> list[DiscoveredDevice]:
        if not _get_refresh_token():
            logger.error("SimpliSafe refresh token not configured")
            return []

        try:
            client = await asyncio.to_thread(_build_client)
            systems = await asyncio.to_thread(client.get_systems)
        except Exception as e:
            _invalidate_client()
            logger.error(f"SimpliSafe discovery failed: {e}")
            return []

        devices: list[DiscoveredDevice] = []

        for system in systems:
            # The system itself is a controllable entity
            entity_id = _slugify(system.name) if system.name else f"simplisafe_{system.subscription_id}"
            devices.append(
                DiscoveredDevice(
                    entity_id=entity_id,
                    name=system.name or "SimpliSafe System",
                    domain="security_system",
                    protocol=self.protocol_name,
                    model=f"SS{system.version}",
                    manufacturer="SimpliSafe",
                    cloud_id=str(system.subscription_id),
                    extra={
                        "alarm_state": system.alarm_state,
                        "is_alarming": system.is_alarming,
                        "version": system.version,
                        "serial": system.serial,
                    },
                )
            )

            # Sensors (read-only)
            try:
                sensors = await asyncio.to_thread(
                    client.get_sensors, system.subscription_id,
                )
                for sensor in sensors:
                    s_id = f"sensor_{_slugify(sensor.name)}" if sensor.name else f"sensor_{_slugify(sensor.serial)}"
                    devices.append(
                        DiscoveredDevice(
                            entity_id=s_id,
                            name=sensor.name,
                            domain="sensor",
                            protocol=self.protocol_name,
                            model=sensor.sensor_type_name,
                            manufacturer="SimpliSafe",
                            cloud_id=sensor.serial,
                            is_controllable=False,
                            extra={
                                "sensor_type": sensor.sensor_type_name,
                                "triggered": sensor.triggered,
                                "offline": sensor.offline,
                                "low_battery": sensor.low_battery,
                                "temperature": sensor.temperature,
                                "subscription_id": system.subscription_id,
                            },
                        )
                    )
            except Exception as e:
                logger.warning(f"Failed to list sensors for system {system.subscription_id}: {e}")

            # Locks
            try:
                locks = await asyncio.to_thread(
                    client.get_locks, system.subscription_id,
                )
                for lock in locks:
                    l_id = f"lock_{_slugify(lock.name)}" if lock.name else f"lock_{_slugify(lock.serial)}"
                    devices.append(
                        DiscoveredDevice(
                            entity_id=l_id,
                            name=lock.name,
                            domain="lock",
                            protocol=self.protocol_name,
                            model="SimpliSafe Lock",
                            manufacturer="SimpliSafe",
                            cloud_id=lock.serial,
                            extra={
                                "state": lock.state,
                                "disabled": lock.disabled,
                                "low_battery": lock.low_battery,
                                "subscription_id": system.subscription_id,
                            },
                        )
                    )
            except Exception as e:
                logger.warning(f"Failed to list locks for system {system.subscription_id}: {e}")

        logger.info(f"SimpliSafe discovery found {len(devices)} device(s)")
        return devices

    async def control(
        self,
        device: DiscoveredDevice,
        action: str,
        params: dict[str, Any] | None = None,
    ) -> DeviceControlResult:
        if not _get_refresh_token():
            return DeviceControlResult(
                success=False,
                entity_id=device.entity_id,
                action=action,
                error="SimpliSafe refresh token not configured",
            )

        try:
            client = await asyncio.to_thread(_build_client)
        except Exception as e:
            _invalidate_client()
            return DeviceControlResult(
                success=False,
                entity_id=device.entity_id,
                action=action,
                error=f"SimpliSafe auth failed: {e}",
            )

        sub_id = device.extra.get("subscription_id") or device.cloud_id
        if not sub_id:
            return DeviceControlResult(
                success=False,
                entity_id=device.entity_id,
                action=action,
                error="No subscription ID found for device",
            )
        sub_id = int(sub_id)
        version = device.extra.get("version", 3)

        try:
            if device.domain == "security_system":
                state_map = {
                    "arm_home": "home",
                    "arm_away": "away",
                    "disarm": "off",
                }
                api_state = state_map.get(action)
                if not api_state:
                    return DeviceControlResult(
                        success=False,
                        entity_id=device.entity_id,
                        action=action,
                        error=f"Unsupported security action: {action}. "
                              f"Use: arm_home, arm_away, disarm",
                    )
                await asyncio.to_thread(
                    client.set_system_state, sub_id, api_state, version,
                )

            elif device.domain == "lock":
                if action not in ("lock", "unlock"):
                    return DeviceControlResult(
                        success=False,
                        entity_id=device.entity_id,
                        action=action,
                        error=f"Unsupported lock action: {action}. Use: lock, unlock",
                    )
                serial = device.cloud_id
                if not serial:
                    return DeviceControlResult(
                        success=False,
                        entity_id=device.entity_id,
                        action=action,
                        error="No serial number for lock",
                    )
                await asyncio.to_thread(
                    client.set_lock_state, sub_id, serial, action,
                )

            elif device.domain == "sensor":
                return DeviceControlResult(
                    success=False,
                    entity_id=device.entity_id,
                    action=action,
                    error="Sensors are read-only — use get_state instead",
                )

            else:
                return DeviceControlResult(
                    success=False,
                    entity_id=device.entity_id,
                    action=action,
                    error=f"Unknown device domain: {device.domain}",
                )

        except Exception as e:
            _invalidate_client()
            return DeviceControlResult(
                success=False,
                entity_id=device.entity_id,
                action=action,
                error=f"Control failed: {e}",
            )

        return DeviceControlResult(
            success=True,
            entity_id=device.entity_id,
            action=action,
        )

    async def get_state(
        self, device: DiscoveredDevice,
    ) -> dict[str, Any]:
        if not _get_refresh_token():
            return {"error": "SimpliSafe refresh token not configured"}

        try:
            client = await asyncio.to_thread(_build_client)
        except Exception as e:
            _invalidate_client()
            return {"error": f"SimpliSafe auth failed: {e}"}

        sub_id = device.extra.get("subscription_id") or device.cloud_id
        if not sub_id:
            return {"error": "No subscription ID found for device"}
        sub_id = int(sub_id)

        try:
            if device.domain == "security_system":
                systems = await asyncio.to_thread(client.get_systems)
                for system in systems:
                    if str(system.subscription_id) == str(device.cloud_id):
                        return {
                            "alarm_state": system.alarm_state,
                            "is_alarming": system.is_alarming,
                            "version": system.version,
                            "serial": system.serial,
                        }
                return {"error": f"System '{device.name}' not found"}

            elif device.domain == "sensor":
                sensors = await asyncio.to_thread(client.get_sensors, sub_id)
                for sensor in sensors:
                    if sensor.serial == device.cloud_id:
                        return {
                            "sensor_type": sensor.sensor_type_name,
                            "triggered": sensor.triggered,
                            "offline": sensor.offline,
                            "low_battery": sensor.low_battery,
                            "temperature": sensor.temperature,
                            "error": sensor.error,
                        }
                return {"error": f"Sensor '{device.name}' not found"}

            elif device.domain == "lock":
                locks = await asyncio.to_thread(client.get_locks, sub_id)
                for lock in locks:
                    if lock.serial == device.cloud_id:
                        return {
                            "state": lock.state,
                            "disabled": lock.disabled,
                            "low_battery": lock.low_battery,
                            "pin_pad_low_battery": lock.pin_pad_low_battery,
                            "pin_pad_offline": lock.pin_pad_offline,
                        }
                return {"error": f"Lock '{device.name}' not found"}

        except Exception as e:
            _invalidate_client()
            return {"error": f"Failed to get state: {e}"}

        return {"error": f"Unknown device domain: {device.domain}"}
