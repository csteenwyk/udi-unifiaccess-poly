# UniFi Access NodeServer for ISY/PG3x

Integrates UniFi Access doors and readers with the ISY/iOX home automation controller via PG3x. Each door appears as a node with position and lock status, with reader sub-nodes for per-reader authentication events — doorbell rings, user identification, auth method, and access results.

## Features

- Real-time events via WebSocket (no polling delay)
- Per-door nodes: position (open/closed), lock status, unlock command
- Per-reader sub-nodes: doorbell ring, last authenticated user, auth method (NFC/PIN/Face/Mobile), access granted/denied
- User identification by name — all Access users loaded automatically on startup
- Doorbell support via webhook (works with UA-Lite, G6 Entry, and other non-intercom readers)
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
| `webhook_host` | eisy IP address (for doorbell webhook receiver) | |
| `webhook_port` | Port for the webhook HTTP server | `7777` |

### Creating an API token

In the **UniFi Access app** (not the main UniFi OS dashboard):

1. Go to **Settings → Integrations → API Tokens**
2. Create a new token
3. Grant **View** on all categories and **People & Groups**, **Edit** on **Device** (required for unlock) and **Webhook** (required for doorbell)
4. Copy the token into the `api_token` custom parameter

### Doorbell setup

The doorbell button sends a webhook-only event (`access.doorbell.incoming`). The plugin registers a webhook automatically on startup — no manual setup required.

You need to:

1. Set `webhook_host` to the eisy's IP address
2. Ensure your firewall allows the UniFi controller to reach the eisy on the configured `webhook_port` (default 7777)

The webhook is registered automatically and cleaned up when the plugin stops. You can verify it exists via the API:

```
curl -sk -H "Authorization: Bearer <token>" https://<host>:12445/api/v1/developer/webhooks/endpoints
```

### User identification

All users are loaded automatically from the Access API when the plugin starts. Their names appear immediately in the ISY `Last User` dropdown without needing to authenticate first. New users added to Access will be picked up on the next plugin restart.

## Node Hierarchy

```
UniFi Access Controller
└── Front Door  (door node)
└── Front Door Reader  (reader sub-node, child of controller)
```

Note: ISY supports only two levels of hierarchy, so reader nodes are children of the controller rather than the door.

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

Granted, Denied, and Doorbell Ring drivers pulse true for 3 seconds then reset, so every event reliably triggers ISY programs even if the same user authenticates back-to-back.

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
   AND 'Front Door Reader' Last User = Chris Steenwyk
Then
   Run Program 'Chris Arrives'
```

Notify when the doorbell is pressed:

```
If
   Control 'Front Door Reader' / Doorbell Ring turns On
Then
   Send Notification 'Someone at the door'
```

## Firewall

The eisy must be able to reach your UniFi controller on port **12445**. The UniFi controller must be able to reach the eisy on port **7777** (or your configured `webhook_port`) for doorbell events.

## License

MIT — see [LICENSE](LICENSE)
