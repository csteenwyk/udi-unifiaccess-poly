# UniFi Access NodeServer for ISY/PG3x

Integrates UniFi Access doors and readers with the ISY/iOX home automation controller via PG3x. Each door appears as a node with position and lock status, with reader sub-nodes for per-reader authentication events — doorbell rings, user identification, auth method, and access results.

## Features

- Real-time events via WebSocket (no polling delay)
- Per-door nodes: position (open/closed), lock status, unlock command
- Per-reader sub-nodes: doorbell ring, last authenticated user, auth method (NFC/PIN/Face/Mobile), access granted/denied
- User identification by name — users auto-learned from events, or pre-configured via custom params
- Local API only — no Ubiquiti cloud required

## Requirements

- UniFi Access controller (UDM Pro, UDM SE, UA Hub, etc.)
- UniFi Access app version 1.x or later
- API token generated inside the Access app (not the UniFi OS control plane)

## Installation

Add the nodeserver in PG3x:

- **GitHub URL**: `https://github.com/csteenwyk/udi-unifiaccess-poly`
- **Executable**: `unifiaccess-poly.py`

## Configuration

Set the following in Custom Parameters:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `host` | IP or hostname of your UniFi controller | |
| `port` | Access developer API port | `12445` |
| `api_token` | API token from the Access app | |
| `verify_ssl` | Verify SSL certificate | `false` |
| `users` | Comma-separated list of known user names | |
| `webhook_host` | eisy IP address (for doorbell webhook receiver) | |
| `webhook_port` | Port for the webhook HTTP server | `7777` |

### Creating an API token

In the **UniFi Access app** (not the main UniFi OS dashboard):

1. Go to **Settings → Integrations → API Tokens**
2. Create a new token
3. Grant **View** on all categories, **Edit** on **Device** (required for unlock)
4. Copy the token into the `api_token` custom parameter

### Pre-configuring users

Set the `users` parameter to a comma-separated list of display names exactly as they appear in UniFi Access:

```
users = "John Smith, Jane Smith, Bob Jones"
```

Users are assigned numbers 1, 2, 3… in order. ISY programs will show their names rather than numbers. Any user not in the list is auto-learned the first time they authenticate — the profile updates automatically and their name appears in subsequent ISY program edits.

## Node Hierarchy

```
UniFi Access Controller
└── Front Door  (door node)
    └── Front Door Reader  (reader sub-node)
```

### Door Node Drivers

| Driver | Description |
|--------|-------------|
| Door Open | Door position sensor (open/closed) |
| Locked | Lock relay status |

### Door Node Commands

| Command | Description |
|---------|-------------|
| Unlock | Send unlock command to Access |

### Reader Node Drivers

| Driver | Description |
|--------|-------------|
| Doorbell Ring | Pulses true when doorbell button pressed |
| Last User | Name of last authenticated user |
| Auth Method | NFC/Card, PIN, Face ID, or Mobile |
| Access Granted | Pulses true on successful authentication |
| Access Denied | Pulses true on denied authentication |

Granted and Denied drivers pulse true for 3 seconds then reset, so every authentication event reliably triggers ISY programs even if the same user authenticates back-to-back.

## Example ISY Program

Unlock a Z-Wave deadbolt when a known user authenticates:

```
If
   Control 'Front Door Reader' / Access Granted turns On
Then
   'Front Door Z-Wave Lock' Unlock
```

Trigger a different scene based on who authenticated:

```
If
   Control 'Front Door Reader' / Access Granted turns On
   AND 'Front Door Reader' Last User = John Smith
Then
   Run Program 'John Arrives'
```

## Firewall

The eisy must be able to reach your UniFi controller on port **12445**. If you have firewall rules blocking IoT → LAN traffic, add an allow rule for the eisy's IP to the controller IP on TCP/12445.

## License

MIT — see [LICENSE](LICENSE)
