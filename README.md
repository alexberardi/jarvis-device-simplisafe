# jarvis-device-simplisafe

SimpliSafe home security device protocol for [Jarvis](https://github.com/alexberardi/jarvis-node-setup).

Arm, disarm, check sensor status, and control locks via the SimpliSafe cloud API.

## Features

- **Arm / Disarm** — set your system to Home, Away, or Off
- **Sensor status** — check doors, motion, glass break, leak, temperature, smoke/CO sensors
- **Lock control** — lock and unlock SimpliSafe smart locks
- **Supports V2 and V3** — works with both system generations

## Setup

### 1. One-time OAuth login

SimpliSafe uses OAuth2 with PKCE and requires a browser-based login with MFA:

```bash
python simplisafe_scripts/authorize.py
```

This will:
1. Print an authorization URL — open it in your browser
2. Log in with your SimpliSafe credentials and complete MFA
3. Copy the redirect URL and paste it back
4. Store the refresh token securely on the node

### 2. Install the package

```bash
cd jarvis-node-setup
python scripts/command_store.py install --local ../jarvis-device-simplisafe
```

## Supported actions

| Domain | Action | Description |
|--------|--------|-------------|
| `security_system` | `arm_home` | Arm in Home mode |
| `security_system` | `arm_away` | Arm in Away mode |
| `security_system` | `disarm` | Disarm the system |
| `lock` | `lock` | Lock a smart lock |
| `lock` | `unlock` | Unlock a smart lock |
| `sensor` | _(read-only)_ | Check status via `get_state` |

## Sensor types

Entry, motion, glass break, smoke, carbon monoxide, leak, temperature, panic button, keypad, siren, camera, doorbell, and more.

## Notes

- SimpliSafe has **no official public API** — this uses the same endpoints as the mobile app and may break without notice
- Refresh tokens are **single-use** — the protocol rotates them automatically
- Avoid polling more than once per 30 seconds to prevent rate limiting
- MFA must be enabled on your SimpliSafe account

## License

MIT
