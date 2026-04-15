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
| `reader_1` … `reader_5` | Protect doorbell device ID and name (see below) | |

### Creating an API token

In the **UniFi Access app** (not the main UniFi OS dashboard):

1. Go to **Settings → Integrations → API Tokens**
2. Create a new token
3. Grant **View** on all categories, **Edit** on **Device** (required for unlock) and **Webhook** (required for doorbell)
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

### Protect doorbell readers (G6, etc.)

UniFi Protect doorbells (like the G6 Entry) are Protect cameras, not Access readers — they never appear in the Access device list. To get a separate ISY node per doorbell, configure `reader_N` params:

```
reader_1 = 69d7222400e0d503e4009952:Front Door
reader_2 = 69dea08000642003e404ea0b:Garage Door
```

Format: `device_id:Display Name`

**How to find the device ID:**

1. Open your UniFi Protect web UI
2. Click on the doorbell camera
3. The camera ID is in the browser URL (the long hex string after `/cameras/`)

Alternatively, ring the doorbell once without any `reader_N` configured — the plugin auto-creates a node and logs the device ID:
```
Auto-creating reader for new doorbell dev=69d7222400e0d5...
```

Each configured reader gets its own ISY node with doorbell ring, last user, auth method, and access granted/denied drivers. If an unknown doorbell rings that isn't in the config, a node is auto-created and persisted for future restarts.

### User identification

All users are loaded automatically from the Access API when the plugin starts. Their names appear immediately in the ISY `Last User` dropdown without needing to authenticate first. New users added to Access will be picked up on the next plugin restart.

## Node Hierarchy

```
UniFi Access Controller
├── Exterior Doors        (door node)
├── Front Door            (reader node — from reader_1 config)
└── Garage Door           (reader node — from reader_2 config)
```

Note: ISY supports only two levels of hierarchy, so reader nodes are children of the controller rather than the door.

### Controller Node Commands

| Command | Description |
|---------|-------------|
| Re-Discover | Re-query doors, devices, users, groups, and policies |
| Set Group Policy | Assign an access policy to a user group (by name) |
| Set User Policy | Assign an access policy to an individual user (by name) |

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

Switch access policy for vacation mode:

```
If
   $Vacation_Mode is True
Then
   Set 'UniFi Access' Group = Family, Policy = Vacation
```

## Firewall

The eisy must be able to reach your UniFi controller on port **12445**. The UniFi controller must be able to reach the eisy on port **7777** (or your configured `webhook_port`) for doorbell events.

## License

MIT — see [LICENSE](LICENSE)
