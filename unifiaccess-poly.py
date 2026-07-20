#!/usr/bin/env python3
"""UniFi Access nodeserver for ISY/PG3x.

Hierarchy:
  Controller
  └── Door node  (position, lock status, unlock command)
      └── Reader node  (doorbell ring, last user, auth method, granted/denied)

Uses the UniFi Access Developer API (port 12445, Bearer token auth).
Token must be created inside the Access app — not the UniFi OS control plane.
"""

import asyncio
import itertools
import json
import os
import ssl
import threading
import time

import aiohttp
import aiohttp.web
import udi_interface

LOGGER = udi_interface.LOGGER

# ---------------------------------------------------------------------------
# API constants
# ---------------------------------------------------------------------------

_API_BASE    = '/api/v1/developer'
_DOORS_URL      = _API_BASE + '/doors'
_DEVICES_URL    = _API_BASE + '/devices'
_WS_URL         = _API_BASE + '/devices/notifications'
_GROUPS_URL     = _API_BASE + '/user_groups'
_POLICIES_URL   = _API_BASE + '/access_policies'

_EVT_LOCATION_UPDATE = 'access.data.device.location_update_v2'
_EVT_V2_LOCATION     = 'access.data.v2.location.update'
_EVT_LOG_ADD         = 'access.logs.insights.add'
_EVT_DOORBELL        = 'access.remote_view'
_EVT_REMOTE_UNLOCK   = 'access.data.device.remote_unlock'

_LOCATION_EVENTS = {_EVT_LOCATION_UPDATE, _EVT_V2_LOCATION,
                    'access.data.location.update'}

_MAX_USERS = 30

# Self-healing: minutes of sustained connection failure before the plugin
# restarts itself, and how long to wait before it's allowed to do so again
# (so a genuinely-down controller doesn't cause a reboot loop).
_WATCHDOG_DEFAULT_MIN = 5
_RESTART_COOLDOWN_SEC = 1800
# Don't raise a user-visible notice for brief blips — only sustained outages.
_NOTICE_AFTER_SEC = 60
# A single press can arrive over both the WebSocket and the webhook; collapse them.
_RING_DEDUP_SEC = 2.0
_WEBHOOK_NAME = 'udi-unifiaccess-poly'

_AUTH_METHOD_MAP = {
    'nfc': 1, 'card': 1, 'rfid': 1,
    'pin': 2, 'keypad': 2, 'code': 2,
    'face': 3, 'fingerprint': 3,
    'mobile': 4, 'bluetooth': 4, 'app': 4,
}

_SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
_NLS_PATH      = os.path.join(_SCRIPT_DIR, 'profile', 'nls', 'en_us.txt')
_USER_MAP_FILE = os.path.join(_SCRIPT_DIR, 'usermap.json')
_WEBHOOK_FILE    = os.path.join(_SCRIPT_DIR, 'webhook.json')
_DOORBELLS_FILE  = os.path.join(_SCRIPT_DIR, 'doorbells.json')

_WEBHOOK_EVENTS = ['access.doorbell.incoming', 'access.doorbell.incoming.REN']
_WEBHOOKS_URL   = _API_BASE + '/webhooks/endpoints'


def _cmd_param(command, param_id, uom, default=0):
    """Extract a named parameter from a multi-param ISY command."""
    query = command.get('query', {})
    key = f'{param_id}.uom{uom}'
    if key in query:
        return int(float(query[key]))
    return int(command.get('value', default))


def _parse_reader_params(params: dict) -> list:
    """Parse reader_N = device_id:Name[:entry|exit] entries from custom params."""
    readers = []
    for key, val in params.items():
        if not key.startswith('reader_') or not val:
            continue
        parts = [p.strip() for p in val.strip().split(':')]
        if len(parts) >= 2:
            entry = {'dev_id': parts[0], 'name': parts[1]}
            if len(parts) >= 3 and parts[2].lower() in ('entry', 'exit'):
                entry['entry_exit'] = parts[2].lower()
            readers.append(entry)
    return readers


def _make_address(raw_id: str) -> str:
    """Derive a stable 14-char ISY node address from any ID string."""
    return raw_id[:14].lower().replace('-', '')


# ---------------------------------------------------------------------------
# User map
# ---------------------------------------------------------------------------

class UserMap:
    """Persistent mapping of Access user UUIDs to stable ISY numeric indices."""

    def __init__(self):
        self._uuid_to_num = {}
        self._name_to_num = {}
        self._num_to_name = {0: 'Unknown'}
        self._next        = 1
        self.changed      = False

    def load(self):
        try:
            with open(_USER_MAP_FILE) as f:
                data = json.load(f)
            for uid, entry in data.get('by_id', {}).items():
                num, name = entry['num'], entry['name']
                self._uuid_to_num[uid]          = num
                self._name_to_num[name.lower()] = num
                self._num_to_name[num]          = name
                if num >= self._next:
                    self._next = num + 1
        except FileNotFoundError:
            pass
        except Exception as e:
            LOGGER.warning(f'Failed to load user map: {e}')

    def save(self):
        by_id = {uid: {'num': num, 'name': self._num_to_name.get(num, '')}
                 for uid, num in self._uuid_to_num.items()}
        try:
            with open(_USER_MAP_FILE, 'w') as f:
                json.dump({'by_id': by_id}, f, indent=2)
            self.changed = False
        except Exception as e:
            LOGGER.warning(f'Failed to save user map: {e}')

    def get_or_add(self, uid: str, display_name: str) -> int:
        if uid and uid in self._uuid_to_num:
            num = self._uuid_to_num[uid]
            if display_name and self._num_to_name.get(num) != display_name:
                self._num_to_name[num]                  = display_name
                self._name_to_num[display_name.lower()] = num
                self.changed = True
            return num

        if display_name:
            key = display_name.lower()
            if key in self._name_to_num:
                num = self._name_to_num[key]
                if uid:
                    self._uuid_to_num[uid] = num
                    self.changed = True
                return num

        if not display_name:
            return 0
        if self._next > _MAX_USERS:
            LOGGER.warning(f'User map full ({_MAX_USERS}), ignoring: {display_name}')
            return 0

        num = self._next
        self._next += 1
        self._uuid_to_num[uid or f'__auto_{num}__'] = num
        self._name_to_num[display_name.lower()]      = num
        self._num_to_name[num]                       = display_name
        self.changed = True
        LOGGER.info(f'Auto-learned user: {display_name} → {num}')
        return num

    def get_uuid(self, num: int) -> str | None:
        """Reverse lookup: NLS index → Access user UUID."""
        for uid, n in self._uuid_to_num.items():
            if n == num and not uid.startswith('__auto_'):
                return uid
        return None

    def nls_lines(self) -> list:
        return [f'AUTH_USER-{n} = {name}'
                for n, name in sorted(self._num_to_name.items())]


# ---------------------------------------------------------------------------
# Profile writer
# ---------------------------------------------------------------------------

_NLS_BASE = """\
# Node Server Names
ND-access_controller-NAME = UniFi Access Controller
ND-access_door-NAME = UniFi Door
ND-access_reader-NAME = UniFi Reader

# Controller Drivers
ST-access_controller-ST-NAME = Status

# Controller Commands
CMD-access_controller-DISCOVER-NAME = Re-Discover
CMD-access_controller-QUERY-NAME = Query All

# Door Drivers
ST-access_door-ST-NAME = Door Open
ST-access_door-GV1-NAME = Locked

# Door Commands
CMD-access_door-QUERY-NAME = Query
CMD-access_door-UNLOCK-NAME = Unlock

# Reader Drivers
ST-access_reader-ST-NAME = Doorbell Ring
ST-access_reader-GV1-NAME = Last User
ST-access_reader-GV2-NAME = Auth Method
ST-access_reader-GV3-NAME = Access Granted
ST-access_reader-GV4-NAME = Access Denied

# Reader Commands
CMD-access_reader-QUERY-NAME = Query

# Controller Policy Commands
CMD-access_controller-SET_GRP_POLICY-NAME = Set Group Policy
CMD-access_controller-SET_USR_POLICY-NAME = Set User Policy
CMDP-group-NAME = Group
CMDP-user-NAME = User
CMDP-policy-NAME = Policy

# Auth Method values (GV2)
AUTH_METHOD-0 = Unknown
AUTH_METHOD-1 = NFC / Card
AUTH_METHOD-2 = PIN
AUTH_METHOD-3 = Face ID
AUTH_METHOD-4 = Mobile

# Users (GV1) - extended dynamically at runtime
"""

_EDITORS_DIR = os.path.join(_SCRIPT_DIR, 'profile', 'editor')


def write_profile(user_map: UserMap, groups: list = None, policies: list = None):
    """Write NLS and editors with dynamic user, group, and policy lists."""
    groups = groups or []
    policies = policies or []

    # --- NLS ---
    nls = _NLS_BASE
    for line in user_map.nls_lines():
        nls += line + '\n'

    nls += '\n# Dynamic — User Groups\n'
    if groups:
        for i, g in enumerate(groups):
            nls += f'CUST_GROUP-{i} = {g["name"]}\n'
    else:
        nls += 'CUST_GROUP-0 = (none)\n'

    nls += '\n# Dynamic — Access Policies\n'
    if policies:
        for i, p in enumerate(policies):
            nls += f'CUST_POLICY-{i} = {p["name"]}\n'
    else:
        nls += 'CUST_POLICY-0 = (none)\n'

    try:
        with open(_NLS_PATH, 'w') as f:
            f.write(nls)
    except Exception as e:
        LOGGER.error(f'Failed to write NLS: {e}')

    # --- Editors ---
    user_subset = ','.join(str(i) for i in range(max(user_map._next, 1)))
    group_subset = ','.join(str(i) for i in range(max(len(groups), 1)))
    policy_subset = ','.join(str(i) for i in range(max(len(policies), 1)))

    editors = f"""<editors>
  <editor id="E_STATUS">
    <range uom="2" subset="0,1"/>
  </editor>
  <editor id="E_AUTH_USER">
    <range uom="56" subset="{user_subset}" nls="AUTH_USER"/>
  </editor>
  <editor id="E_AUTH_METHOD">
    <range uom="56" subset="0,1,2,3,4" nls="AUTH_METHOD"/>
  </editor>
  <editor id="E_GROUP">
    <range uom="25" subset="{group_subset}" nls="CUST_GROUP"/>
  </editor>
  <editor id="E_POLICY">
    <range uom="25" subset="{policy_subset}" nls="CUST_POLICY"/>
  </editor>
</editors>
"""
    try:
        with open(os.path.join(_EDITORS_DIR, 'editors.xml'), 'w') as f:
            f.write(editors)
    except Exception as e:
        LOGGER.error(f'Failed to write editors: {e}')

    LOGGER.info(f'Profile updated: {user_map._next} user(s), '
                f'{len(groups)} group(s), {len(policies)} policy(ies)')


# ---------------------------------------------------------------------------
# UniFi Access API client
# ---------------------------------------------------------------------------

class AccessClient:

    def __init__(self, host, port, api_token, verify_ssl=False):
        self.host      = host
        self.port      = port
        self.api_token = api_token
        self._ssl      = ssl.create_default_context() if verify_ssl else False
        self._session  = None

    def _url(self, path):
        return f'https://{self.host}:{self.port}{path}'

    def _ws_url(self):
        return f'wss://{self.host}:{self.port}{_WS_URL}'

    def _headers(self):
        return {'Authorization': f'Bearer {self.api_token}'}

    async def connect(self):
        # Bound connection ESTABLISHMENT only. A blackholed route (no ICMP
        # unreachable — what a lost route actually looks like) hangs the TCP
        # connect, which is the case we care about.
        # Deliberately no `total`: this session is also used for ws_connect,
        # and a total timeout applies to the whole upgraded connection, which
        # would tear down a healthy WebSocket on a timer.
        self._session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            timeout=aiohttp.ClientTimeout(total=None, connect=10, sock_connect=10))

    async def get_users(self) -> list:
        resp = await self._session.get(
            self._url(_API_BASE + '/users'), headers=self._headers(), ssl=self._ssl)
        resp.raise_for_status()
        return (await resp.json()).get('data') or []

    async def get_doors(self) -> list:
        resp = await self._session.get(
            self._url(_DOORS_URL), headers=self._headers(), ssl=self._ssl)
        resp.raise_for_status()
        return (await resp.json()).get('data') or []

    async def get_devices(self) -> list:
        resp = await self._session.get(
            self._url(_DEVICES_URL), headers=self._headers(), ssl=self._ssl)
        resp.raise_for_status()
        raw = (await resp.json()).get('data') or []
        # API returns nested arrays: [[device, ...], [device, ...], ...]
        return [d for group in raw
                for d in (group if isinstance(group, list) else [group])]

    async def unlock_door(self, door_id):
        resp = await self._session.put(
            self._url(f'{_DOORS_URL}/{door_id}/unlock'),
            headers=self._headers(), ssl=self._ssl)
        resp.raise_for_status()

    async def get_user_groups(self) -> list:
        resp = await self._session.get(
            self._url(_GROUPS_URL), headers=self._headers(), ssl=self._ssl)
        resp.raise_for_status()
        return (await resp.json()).get('data') or []

    async def get_access_policies(self) -> list:
        resp = await self._session.get(
            self._url(_POLICIES_URL), headers=self._headers(), ssl=self._ssl)
        resp.raise_for_status()
        return (await resp.json()).get('data') or []

    async def set_group_policies(self, group_id: str, policy_ids: list):
        resp = await self._session.put(
            self._url(f'{_GROUPS_URL}/{group_id}/access_policies'),
            headers=self._headers(), ssl=self._ssl,
            json={'access_policy_ids': policy_ids})
        resp.raise_for_status()

    async def set_user_policies(self, user_id: str, policy_ids: list):
        resp = await self._session.put(
            self._url(f'{_API_BASE}/users/{user_id}/access_policies'),
            headers=self._headers(), ssl=self._ssl,
            json={'access_policy_ids': policy_ids})
        resp.raise_for_status()

    async def listen(self, on_message, on_connect=None):
        async with self._session.ws_connect(
                self._ws_url(), headers=self._headers(),
                ssl=self._ssl, heartbeat=30) as ws:
            # Fires only once the socket is genuinely established — this is the
            # only trustworthy "we are online" signal.
            if on_connect:
                on_connect()
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        payload = json.loads(msg.data)
                    except Exception:
                        continue
                    if not isinstance(payload, dict):
                        continue
                    event = payload.get('event') or payload.get('type', '')
                    if event == 'Hello':
                        continue
                    await on_message(event, payload.get('data', {}))
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    LOGGER.warning(f'WebSocket {msg.type}')
                    break

    async def find_webhook(self, name: str) -> str | None:
        """Return the ID of an existing webhook with the given name, or None."""
        try:
            resp = await self._session.get(
                self._url(_WEBHOOKS_URL), headers=self._headers(), ssl=self._ssl)
            resp.raise_for_status()
            for wh in (await resp.json()).get('data', []):
                if wh.get('name') == name:
                    return wh.get('id')
        except Exception as e:
            LOGGER.warning(f'Failed to list webhooks: {e}')
        return None

    async def register_webhook(self, url: str, webhook_id: str = None) -> dict:
        payload = {'name': 'udi-unifiaccess-poly',
                   'endpoint': url, 'events': _WEBHOOK_EVENTS}
        if webhook_id:
            resp = await self._session.put(
                self._url(f'{_WEBHOOKS_URL}/{webhook_id}'),
                headers=self._headers(), ssl=self._ssl, json=payload)
        else:
            resp = await self._session.post(
                self._url(_WEBHOOKS_URL),
                headers=self._headers(), ssl=self._ssl, json=payload)
        resp.raise_for_status()
        return (await resp.json()).get('data', {})

    async def delete_webhook(self, webhook_id: str):
        try:
            resp = await self._session.delete(
                self._url(f'{_WEBHOOKS_URL}/{webhook_id}'),
                headers=self._headers(), ssl=self._ssl)
            resp.raise_for_status()
        except Exception as e:
            LOGGER.warning(f'Failed to delete webhook {webhook_id}: {e}')

    async def reconnect(self):
        await self.close()
        await self.connect()

    async def close(self):
        if self._session:
            await self._session.close()
            self._session = None


# ---------------------------------------------------------------------------
# Async bridge
# ---------------------------------------------------------------------------

class _AsyncBridge:
    def __init__(self):
        self._loop   = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever,
                                        daemon=True, name='unifiaccess-async')
        self._thread.start()

    def run(self, coro, timeout=30):
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=timeout)
        except Exception as e:
            LOGGER.error(f'Async error: {e}')
            return None

    def submit(self, coro, label='task'):
        """Fire-and-forget, but never silently: failures are logged."""
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        future.add_done_callback(lambda f: self._log_failure(f, label))
        return future

    @staticmethod
    def _log_failure(future, label):
        try:
            future.result()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            LOGGER.error(f'Async {label} failed: {e}', exc_info=True)

    def shutdown(self):
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Webhook HTTP server
# ---------------------------------------------------------------------------

class WebhookServer:
    """Tiny aiohttp server that receives doorbell POSTs from UniFi Access."""

    def __init__(self, port: int, on_doorbell):
        self._port       = port
        self._on_doorbell = on_doorbell
        self._runner     = None

    async def start(self):
        app = aiohttp.web.Application()
        app.router.add_post('/webhook', self._handle)
        self._runner = aiohttp.web.AppRunner(app)
        await self._runner.setup()
        await aiohttp.web.TCPSite(self._runner, '0.0.0.0', self._port).start()
        LOGGER.info(f'Webhook server listening on port {self._port}')

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
            self._runner = None

    async def _handle(self, request):
        try:
            body = await request.json()
            event = body.get('event', '')
            if event in ('access.doorbell.incoming', 'access.doorbell.incoming.REN'):
                LOGGER.info(f'Webhook doorbell: {event}')
                await self._on_doorbell(body.get('data', {}))
        except Exception as e:
            LOGGER.error(f'Webhook handler error: {e}')
        return aiohttp.web.Response(text='OK')


# ---------------------------------------------------------------------------
# Reader node (child of door)
# ---------------------------------------------------------------------------

class ReaderNode(udi_interface.Node):
    id = 'access_reader'

    drivers = [
        {'driver': 'ST',  'value': 0, 'uom': 2},   # doorbell ring (pulse)
        {'driver': 'GV1', 'value': 0, 'uom': 56},  # last user (→ name via NLS)
        {'driver': 'GV2', 'value': 0, 'uom': 56},  # auth method
        {'driver': 'GV3', 'value': 0, 'uom': 2},   # access granted (pulse)
        {'driver': 'GV4', 'value': 0, 'uom': 2},   # access denied (pulse)
    ]

    def __init__(self, polyglot, primary, address, name, device_id):
        super().__init__(polyglot, primary, address, name)
        self.device_id = device_id

    def ring(self):
        self.setDriver('ST', 1, report=True, force=True)

    def set_user(self, num: int):
        self.setDriver('GV1', num, report=True, force=True)

    def set_auth_method(self, method: str):
        m = method.lower()
        val = next((num for key, num in _AUTH_METHOD_MAP.items() if key in m), 0)
        self.setDriver('GV2', val, report=True, force=True)

    def set_granted(self, granted: bool):
        driver = 'GV3' if granted else 'GV4'
        self.setDriver(driver, 1, report=True, force=True)

    def query(self, command=None):
        self.reportDrivers()

    commands = {'QUERY': query}


# ---------------------------------------------------------------------------
# Door node (child of controller, parent of readers)
# ---------------------------------------------------------------------------

class DoorNode(udi_interface.Node):
    id = 'access_door'

    drivers = [
        {'driver': 'ST',  'value': 0, 'uom': 2},  # door open
        {'driver': 'GV1', 'value': 1, 'uom': 2},  # locked
    ]

    def __init__(self, polyglot, primary, address, name, door_id, controller):
        super().__init__(polyglot, primary, address, name)
        self.door_id     = door_id
        self._controller = controller

    def set_position(self, status: str):
        self.setDriver('ST', 1 if status == 'open' else 0,
                       report=True, force=False)

    def set_locked(self, status: str):
        self.setDriver('GV1', 1 if status in ('lock', 'locked') else 0,
                       report=True, force=False)

    def query(self, command=None):
        self.reportDrivers()

    def cmd_unlock(self, command=None):
        self._controller.unlock_door(self.door_id)

    commands = {'QUERY': query, 'UNLOCK': cmd_unlock}


# ---------------------------------------------------------------------------
# Controller node
# ---------------------------------------------------------------------------

class Controller(udi_interface.Node):
    id = 'access_controller'

    drivers = [{'driver': 'ST', 'value': 0, 'uom': 2}]

    def __init__(self, polyglot, primary, address, name):
        super().__init__(polyglot, primary, address, name)

        self._async             = _AsyncBridge()
        self._client            = None
        self._webhook_server    = None
        self._webhook_id        = None
        self._doors             = {}   # address     → DoorNode
        self._door_by_id        = {}   # door_id     → DoorNode
        self._readers           = {}   # address     → ReaderNode
        self._reader_by_dev     = {}   # device_id   → ReaderNode
        self._readers_by_door   = {}   # door_addr   → [ReaderNode]
        self._reader_by_entry   = {}   # (door_addr, 'entry'|'exit') → ReaderNode
        self._groups            = []   # [{id, name}, ...]
        self._policies          = []   # [{id, name}, ...]
        self._initialized       = False
        self._controller_added  = False
        self._node_events       = {}   # node address → threading.Event
        self._node_events_lock  = threading.Lock()
        self._params            = udi_interface.Custom(polyglot, 'customparams')
        self._data              = udi_interface.Custom(polyglot, 'customdata')
        self._users             = UserMap()
        self._down_since        = None  # epoch of first failure in current outage
        self._watchdog_minutes  = _WATCHDOG_DEFAULT_MIN
        self._running           = True
        self._connect_lock      = threading.Lock()
        self._profile_written   = False
        self._webhook_started   = False
        self._last_ring         = {}   # dev_id → epoch of last ring

        polyglot.subscribe(polyglot.CONFIGDONE,   self._on_config_done)
        polyglot.subscribe(polyglot.START,        self.start)
        polyglot.subscribe(polyglot.CUSTOMPARAMS, self.param_handler)
        polyglot.subscribe(polyglot.CUSTOMDATA,   self._customdata_handler)
        polyglot.subscribe(polyglot.POLL,         self.poll)
        polyglot.subscribe(polyglot.STOP,         self.stop)
        polyglot.subscribe(polyglot.ADDNODEDONE,  self._on_node_added)

        polyglot.ready()
        polyglot.addNode(self)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        LOGGER.debug('start()')

    def _customdata_handler(self, data):
        """Custom() does not self-load — without this the watchdog's restart
        cooldown would read None every start and could reboot-loop."""
        self._data.load(data or {})

    def stop(self):
        LOGGER.info('Stopping UniFi Access nodeserver')
        self._running = False
        if self._client and self._webhook_id:
            self._async.run(self._client.delete_webhook(self._webhook_id), timeout=10)
        if self._webhook_server:
            self._async.run(self._webhook_server.stop(), timeout=5)
        if self._client:
            self._async.run(self._client.close(), timeout=10)
        self._async.shutdown()

    def _on_config_done(self):
        if self._controller_added:
            return
        try:
            self._add_node_wait(self, timeout=3)
            self._controller_added = True
            # ST reflects the UniFi connection, not node creation. Claiming 1
            # here made the controller look healthy for an entire outage.
            self.setDriver('ST', 0)
            if not self._initialized:
                self._try_connect()
        except Exception as e:
            LOGGER.error(f'Failed to add controller node: {e}', exc_info=True)

    def _on_node_added(self, data):
        addr = (data or {}).get('address')
        with self._node_events_lock:
            if addr is None:
                # Payload without an address: we can't tell who it was for,
                # so wake everyone rather than hang every waiter.
                waiters = list(self._node_events.values())
            else:
                # A known address with no waiter means a late or duplicate ack.
                # Waking someone else here is exactly the cross-wake this
                # per-address scheme exists to prevent.
                ev = self._node_events.get(addr)
                waiters = [ev] if ev else []
        for e in waiters:
            e.set()

    def _add_node_wait(self, node, timeout=15):
        # One Event per address: a single shared Event let concurrent callers
        # consume each other's completion and return before their node existed.
        ev = threading.Event()
        with self._node_events_lock:
            self._node_events[node.address] = ev
        try:
            self.poly.addNode(node)
            if not ev.wait(timeout=timeout):
                LOGGER.warning(f'Timed out waiting for ISY to add {node.address}')
        finally:
            with self._node_events_lock:
                self._node_events.pop(node.address, None)

    # ------------------------------------------------------------------
    # Params / connection
    # ------------------------------------------------------------------

    def param_handler(self, params):
        # PG3 always publishes CUSTOMPARAMS at startup, but with a None payload
        # when it has nothing stored. Loading that would wipe _rawdata, and
        # params.get() would raise inside a bare handler thread — silently
        # leaving the plugin configured-but-never-connected.
        if not params:
            LOGGER.warning('CUSTOMPARAMS with no data — keeping existing params')
            return
        self._params.load(params)
        # Targeted delete, not clear() — clear() would also wipe an active
        # outage notice every time params are saved.
        self.poly.Notices.delete('config')
        host      = (params.get('host')      or '').strip()
        api_token = (params.get('api_token') or '').strip()
        if not host or not api_token:
            self.poly.Notices['config'] = 'Set host and api_token in Custom Parameters'
            return
        if not self._initialized:
            self._try_connect()

    def _is_configured(self) -> bool:
        if ((self._params.get('host') or '').strip()
                and (self._params.get('api_token') or '').strip()):
            return True
        # _params can be empty if CUSTOMPARAMS never reached us. PG3's config is
        # the authoritative copy, so fall back to it rather than staying dead.
        try:
            cfg = (self.poly.getConfig() or {}).get('customParams') or {}
        except Exception:
            return False
        if (cfg.get('host') or '').strip() and (cfg.get('api_token') or '').strip():
            LOGGER.warning('Recovered params from PG3 config')
            self._params.load(cfg)
            return True
        return False

    def _try_connect(self):
        # CONFIGDONE, CUSTOMPARAMS and POLL each run on their own thread, so a
        # bare check-then-set would let two supervisors start against two
        # clients, leaking a session and orphaning a loop.
        with self._connect_lock:
            if self._initialized:
                return
            self._initialized = True

        params        = self._params
        host          = (params.get('host')         or '').strip()
        api_token     = (params.get('api_token')    or '').strip()
        port          = int((params.get('port')     or '12445').strip())
        verify        = (params.get('verify_ssl')   or 'false').strip().lower() == 'true'
        webhook_host  = (params.get('webhook_host') or '').strip()
        webhook_port  = int((params.get('webhook_port') or '7777').strip())
        try:
            self._watchdog_minutes = int(
                (params.get('watchdog_minutes') or _WATCHDOG_DEFAULT_MIN))
        except ValueError:
            self._watchdog_minutes = _WATCHDOG_DEFAULT_MIN

        if not host or not api_token:
            LOGGER.warning('host/api_token not set — not connecting')
            self._initialized = False
            return

        # Profile work is expensive and only needs doing once per process;
        # a retry loop must not re-upload the ISY profile on every attempt.
        if not self._profile_written:
            self._users.load()
            write_profile(self._users)
            self._users.save()
            try:
                self.poly.updateProfile()
                LOGGER.info('Profile uploaded to ISY')
            except Exception as e:
                LOGGER.warning(f'updateProfile failed: {e}')
            self._profile_written = True

        self._async.submit(
            self._supervisor(host, port, api_token, verify, webhook_host, webhook_port),
            'connection supervisor')

    async def _supervisor(self, host, port, api_token, verify_ssl,
                          webhook_host='', webhook_port=7777):
        """Owns the whole connection lifecycle.

        First connect and reconnect-after-an-outage are deliberately the same
        code path: a failure at any stage just falls through to the backoff and
        tries again. Nothing here is one-shot, so a plugin that starts before
        the network is up simply retries until the network arrives.
        """
        try:
            await self._supervise(host, port, api_token, verify_ssl,
                                  webhook_host, webhook_port)
        finally:
            # Every exit path — clean stop or an unexpected crash — must clear
            # this, or the shortPoll safety net won't restart us and we're a
            # zombie again.
            LOGGER.info('Connection supervisor stopped')
            self._initialized = False

    async def _supervise(self, host, port, api_token, verify_ssl,
                         webhook_host='', webhook_port=7777):
        backoff = 5
        first = True
        while self._running:
            try:
                LOGGER.info(f'Connecting to UniFi Access at {host}:{port}')
                self._client = AccessClient(host, port, api_token, verify_ssl)
                await self._client.connect()

                if first:
                    # Let ISY digest the profile upload before we add nodes
                    await asyncio.sleep(3)
                    first = False

                # REST first: proves routing, TLS and token before we commit
                # to a WebSocket, and gives a clean error if any of them fail.
                await self._fetch_and_discover()

                # Re-registered on EVERY connect. Registering once at startup
                # left doorbells silently dead after any reconnect.
                if webhook_host:
                    await self._ensure_webhook(webhook_host, webhook_port)

                LOGGER.info('Listening for WebSocket events')
                backoff = 5
                # _mark_online fires from inside, once the socket is truly up.
                await self._client.listen(self._on_ws_message,
                                          on_connect=self._mark_online)
                LOGGER.warning('WebSocket closed by peer')
                self._mark_offline('WebSocket closed')
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self._mark_offline(e)

            await self._teardown_client()
            if not self._running:
                break
            LOGGER.info(f'Retrying in {backoff}s')
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)

    async def _teardown_client(self):
        self.setDriver('ST', 0)
        client, self._client = self._client, None
        if client:
            try:
                await client.close()
            except Exception as e:
                LOGGER.debug(f'Error closing client: {e}')

    def _mark_online(self):
        """Called only when the WebSocket is genuinely established."""
        self.setDriver('ST', 1)
        if self._down_since is not None:
            down_min = (time.time() - self._down_since) / 60
            LOGGER.info(f'Connection restored after {down_min:.1f} min offline')
            self._down_since = None
        self.poly.Notices.delete('offline')

    def _mark_offline(self, err):
        """Track a sustained outage: surface it, then self-restart if it persists."""
        now = time.time()
        if self._down_since is None:
            self._down_since = now
        down_sec = now - self._down_since
        LOGGER.warning(f'Connection failed (down {down_sec / 60:.1f} min): {err}')

        if down_sec >= _NOTICE_AFTER_SEC:
            self.poly.Notices['offline'] = (
                f'No connection to UniFi Access for {down_sec / 60:.0f} min: {err}')

        if not self._watchdog_minutes or down_sec < self._watchdog_minutes * 60:
            return

        # Sustained outage. Restarting is a blunt last resort — the retry loop
        # above is the real recovery path, and restart() is a no-op anyway if
        # MQTT never came up. Cooldown is persisted so it survives the restart
        # it just caused; without that this would reboot-loop.
        last = float(self._data.get('last_restart') or 0)
        if now - last < _RESTART_COOLDOWN_SEC:
            return
        self._data['last_restart'] = now
        LOGGER.error(f'No connection for {down_sec / 60:.0f} min — restarting plugin')
        try:
            self.poly.restart()
        except Exception as e:
            LOGGER.error(f'Self-restart failed: {e}')

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def _fetch_and_discover(self):
        doors, devices, users, groups, policies = await asyncio.gather(
            self._client.get_doors(),
            self._client.get_devices(),
            self._client.get_users(),
            self._client.get_user_groups(),
            self._client.get_access_policies(),
        )
        LOGGER.info(f'Discovered {len(doors)} door(s), {len(devices)} device(s), '
                    f'{len(users)} user(s), {len(groups)} group(s), {len(policies)} policy(ies)')
        for u in users:
            uid  = u.get('id', '')
            name = u.get('full_name') or u.get('first_name', '')
            if uid and name:
                self._users.get_or_add(uid, name)

        # Rebuild profile if users changed or group/policy lists changed
        old_groups = len(self._groups)
        old_policies = len(self._policies)
        self._groups = [{'id': g['id'], 'name': g.get('name', g['id'])}
                        for g in groups if g.get('id')]
        self._policies = [{'id': p['id'], 'name': p.get('name', p['id'])}
                          for p in policies if p.get('id')]
        if (self._users.changed
                or len(self._groups) != old_groups
                or len(self._policies) != old_policies):
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._save_and_rebuild_profile)
        # _discover blocks waiting for ISY to confirm each addNode. Run it off
        # the event loop or a large discovery starves the webhook server and
        # the WebSocket heartbeat, which drops the socket mid-discovery.
        await asyncio.get_event_loop().run_in_executor(
            None, self._discover, doors, devices)

    def _discover(self, doors: list, devices: list):
        door_id_to_addr = {}
        for door in doors:
            node = self._ensure_door(door)
            if node:
                door_id_to_addr[door['id']] = node.address

        # Build hub→door map: hub's location_id == door_id
        device_by_id = {d['id']: d for d in devices}
        hub_to_door  = {
            dev['id']: dev['location_id']
            for dev in devices
            if 'is_hub' in dev.get('capabilities', [])
            and dev.get('location_id') in door_id_to_addr
        }

        for dev in devices:
            caps = dev.get('capabilities', [])
            if 'is_reader' not in caps and 'is_doorbell' not in caps:
                continue

            loc = dev.get('location_id', '')
            door_id = None

            if loc in door_id_to_addr:
                door_id = loc
            else:
                # Reader is at the same location as a hub whose location is a door
                door_id = next(
                    (hdoor for hid, hdoor in hub_to_door.items()
                     if device_by_id.get(hid, {}).get('location_id') == loc),
                    None
                )

            if not door_id and len(door_id_to_addr) == 1:
                door_id = next(iter(door_id_to_addr))

            door_addr = door_id_to_addr.get(door_id, self.address)
            self._ensure_reader(dev, door_addr)

        # Create reader nodes for configured reader_N params (Protect doorbells
        # that don't appear in get_devices()). Fall back to loading any
        # auto-created doorbells from doorbells.json.
        configured_readers = _parse_reader_params(dict(self._params))
        for cr in configured_readers:
            dev_id = cr['dev_id']
            if dev_id not in self._reader_by_dev:
                door_addr = next(iter(door_id_to_addr.values()), self.address)
                self._ensure_configured_reader(dev_id, cr['name'], door_addr,
                                               cr.get('entry_exit', ''))

        # Load auto-created doorbells from persistence
        self._load_persisted_doorbells(door_id_to_addr)

    def _ensure_door(self, door: dict):
        door_id = door.get('id', '')
        if not door_id:
            return None
        address = _make_address(door_id)
        if address in self._doors:
            node = self._doors[address]
            node.set_position(door.get('door_position_status', 'none'))
            node.set_locked(door.get('door_lock_relay_status', 'lock'))
            return node
        name = door.get('name') or door_id
        node = DoorNode(self.poly, self.address, address, name, door_id, self)
        self._add_node_wait(node, timeout=3)
        node.set_position(door.get('door_position_status', 'none'))
        node.set_locked(door.get('door_lock_relay_status', 'lock'))
        self._doors[address]    = node
        self._door_by_id[door_id] = node
        LOGGER.info(f'Added door: {name} ({address})')
        return node

    def _ensure_reader(self, dev: dict, door_address: str):
        dev_id = dev.get('id', '')
        if not dev_id:
            return None
        address = _make_address(dev_id)
        node = self._readers.get(address)
        if node is None:
            name = dev.get('alias') or dev.get('name') or dev_id
            # ISY only supports 2-level hierarchy; all nodes must be children of controller
            node = ReaderNode(self.poly, self.address, address, name, dev_id)
            self._add_node_wait(node, timeout=3)
            self._readers[address] = node
            LOGGER.info(f'Added reader: {name} ({address}) under {door_address}')
        # Index maintenance runs even for an existing node: a reader created
        # during a partial discovery can be filed under the wrong door, and
        # an early return would leave that wrong forever.
        self._reader_by_dev[dev_id] = node
        by_door = self._readers_by_door.setdefault(door_address, [])
        if node not in by_door:
            by_door.append(node)
        return node

    def _ensure_configured_reader(self, dev_id: str, name: str, door_address: str,
                                   entry_exit: str = ''):
        """Create (or reuse) a reader node for a configured Protect doorbell."""
        address = _make_address(dev_id)
        node = self._readers.get(address)
        if node is None:
            node = ReaderNode(self.poly, self.address, address, name, dev_id)
            self._add_node_wait(node, timeout=3)
            self._readers[address] = node
            LOGGER.info(f'Added configured reader: {name} ({address}) dev={dev_id[:12]}... {entry_exit or ""}')
        # See _ensure_reader: indexes are refreshed even on the reuse path.
        self._reader_by_dev[dev_id] = node
        by_door = self._readers_by_door.setdefault(door_address, [])
        if node not in by_door:
            by_door.append(node)
        if entry_exit:
            self._reader_by_entry[(door_address, entry_exit)] = node
        return node

    def _auto_create_reader(self, dev_id: str, door_id: str):
        """Auto-create a reader on first ring from an unknown device. Persist for restarts."""
        door = self._door_by_id.get(door_id)
        door_addr = door.address if door else self.address
        door_name = door.name if door else 'Unknown'
        # Count existing readers on this door for numbering
        existing = len(self._readers_by_door.get(door_addr, []))
        suffix = f' {existing + 1}' if existing > 0 else ''
        name = f'{door_name} Doorbell{suffix}'
        node = self._ensure_configured_reader(dev_id, name, door_addr)
        # Persist for future restarts
        self._save_doorbell(dev_id, name, door_id)
        return node

    def _save_doorbell(self, dev_id: str, name: str, door_id: str):
        """Append a doorbell entry to doorbells.json."""
        try:
            try:
                with open(_DOORBELLS_FILE) as f:
                    data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                data = {}
            data[dev_id] = {'name': name, 'door_id': door_id}
            with open(_DOORBELLS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            LOGGER.warning(f'Failed to save doorbell: {e}')

    def _load_persisted_doorbells(self, door_id_to_addr: dict):
        """Load auto-created doorbells from doorbells.json."""
        try:
            with open(_DOORBELLS_FILE) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return
        except Exception as e:
            LOGGER.warning(f'Failed to load doorbells: {e}')
            return
        for dev_id, info in data.items():
            if dev_id in self._reader_by_dev:
                continue  # already created from config
            door_id = info.get('door_id', '')
            door_addr = door_id_to_addr.get(door_id, self.address)
            name = info.get('name', dev_id)
            self._ensure_configured_reader(dev_id, name, door_addr)

    # ------------------------------------------------------------------
    # WebSocket event handling  (async — no blocking I/O on this thread)
    # ------------------------------------------------------------------

    async def _on_ws_message(self, event: str, data: dict):
        try:
            if event in _LOCATION_EVENTS:
                self._handle_location_update(data)
            elif event == _EVT_LOG_ADD:
                await self._handle_log_event(data)
            elif event == _EVT_DOORBELL:
                self._handle_doorbell(data)
            elif event == _EVT_REMOTE_UNLOCK:
                self._handle_remote_unlock(data)
        except Exception as e:
            LOGGER.error(f'WS message error: {e}', exc_info=True)

    def _handle_location_update(self, data: dict):
        door = self._door_by_id.get(data.get('id', ''))
        if not door:
            return
        state = data.get('state', {})
        if state.get('dps'):
            door.set_position(state['dps'])
        if state.get('lock'):
            door.set_locked(state['lock'])

    def _handle_remote_unlock(self, data: dict):
        # data has door fields (unique_id, name, location_type='door')
        door = self._door_by_id.get(data.get('unique_id', ''))
        if door:
            door.set_locked('unlock')
            LOGGER.info(f'Remote unlock: {door.name}')

    def _handle_doorbell(self, data: dict):
        # WebSocket access.remote_view: data.device_id = reader device ID
        dev_id = data.get('device_id') or data.get('deviceId') or data.get('id') or ''
        self._ring_doorbell(dev_id=dev_id, door_id=None)

    async def _on_webhook_doorbell(self, data: dict):
        # Webhook access.doorbell.incoming: data.device.id, data.location.id
        dev_id  = (data.get('device')   or {}).get('id', '')
        door_id = (data.get('location') or {}).get('id', '')
        self._ring_doorbell(dev_id=dev_id, door_id=door_id)

    def _ring_doorbell(self, dev_id: str, door_id: str):
        # One press can arrive twice: the WebSocket access.remote_view event
        # and the access.doorbell.incoming webhook. ring() uses force=True, so
        # without this ISY sees two Control events and every doorbell program
        # fires twice.
        key = dev_id or door_id or '?'
        now = time.time()
        if now - self._last_ring.get(key, 0) < _RING_DEDUP_SEC:
            LOGGER.debug(f'Ignoring duplicate doorbell ring for {key[:12]}')
            return
        self._last_ring[key] = now

        reader = self._reader_by_dev.get(dev_id)
        if not reader and dev_id:
            # Unknown device — auto-create a reader node for it
            LOGGER.info(f'Auto-creating reader for new doorbell dev={dev_id[:12]}...')
            reader = self._auto_create_reader(dev_id, door_id or '')
        if not reader and door_id:
            door = self._door_by_id.get(door_id)
            if door:
                readers = self._readers_by_door.get(door.address, [])
                reader = readers[0] if readers else None
        if not reader and self._readers:
            reader = next(iter(self._readers.values()))
        if reader:
            reader.ring()
            asyncio.create_task(self._reset_driver(reader, 'ST'))
            LOGGER.info(f'Doorbell ring: {reader.name}')
        else:
            LOGGER.info(f'Doorbell: no reader found (dev={dev_id!r} door={door_id!r})')

    async def _handle_log_event(self, data: dict):
        # data.result == 'ACCESS' for granted; everything else in data.metadata
        granted  = data.get('result', '') == 'ACCESS'
        metadata = data.get('metadata', {})

        actor  = metadata.get('actor') or {}
        uid    = actor.get('id', '')
        name   = actor.get('display_name') or ''

        auth   = metadata.get('authentication') or {}
        method = auth.get('credential_provider') or auth.get('display_name') or ''

        user_num = self._users.get_or_add(uid, name)
        if self._users.changed:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._save_and_rebuild_profile)

        status = 'GRANTED' if granted else 'DENIED'
        LOGGER.info(f'Access {status}: {name or uid} via {method or "?"} (user={user_num})')

        # Route auth event to the correct reader by entry/exit if configured
        door_id = (metadata.get('door') or {}).get('id', '')
        door    = self._door_by_id.get(door_id)
        reader  = None
        if door:
            # Check target for door_entry_method to distinguish entry vs exit
            targets = metadata.get('target') or data.get('target') or []
            # Route by camera ID (Protect device) — works for all auth methods
            cam_id = (metadata.get('camera') or {}).get('id', '')
            if cam_id:
                reader = self._reader_by_dev.get(cam_id)
            # Fall back to entry/exit routing
            if not reader:
                dev_cfg = metadata.get('device_config') or {}
                entry_method = (dev_cfg.get('display_name') or '').lower()
                if entry_method:
                    reader = self._reader_by_entry.get((door.address, entry_method))
            if not reader:
                readers = self._readers_by_door.get(door.address, [])
                reader = readers[0] if readers else None
        if not reader and self._readers:
            reader = next(iter(self._readers.values()))

        if reader:
            reader.set_user(user_num)
            reader.set_auth_method(method)
            reader.set_granted(granted)
            asyncio.create_task(
                self._reset_driver(reader, 'GV3' if granted else 'GV4'))

    # ------------------------------------------------------------------
    # Webhook
    # ------------------------------------------------------------------

    async def _ensure_webhook(self, webhook_host: str, webhook_port: int):
        """Bring up the local listener and (re)register it with the controller.

        Called on every connect. Registration failure must not prevent the
        local listener from running, and must not abort the connection —
        previously either one left doorbells permanently dead while the plugin
        still reported healthy.
        """
        if not self._webhook_started:
            try:
                self._webhook_server = WebhookServer(webhook_port,
                                                     self._on_webhook_doorbell)
                await self._webhook_server.start()
                self._webhook_started = True
            except Exception as e:
                LOGGER.error(f'Webhook server failed to bind port {webhook_port}: {e}')
                self._webhook_server = None
                self.poly.Notices['webhook'] = (
                    f'Doorbell listener could not bind port {webhook_port}: {e}')
                return

        url = f'http://{webhook_host}:{webhook_port}/webhook'
        try:
            # Look the ID up by name every time rather than trusting a cached
            # one — a stale ID from a previous run 404s on update, and that
            # used to be unrecoverable.
            existing = await self._client.find_webhook(_WEBHOOK_NAME)
            info = await self._client.register_webhook(url, existing)
            self._webhook_id = info.get('id') or existing
            try:
                with open(_WEBHOOK_FILE, 'w') as f:
                    json.dump({'id': self._webhook_id}, f)
            except Exception as e:
                LOGGER.debug(f'Could not persist webhook id: {e}')
            LOGGER.info(f'Webhook registered: {url} (id={self._webhook_id})')
            self.poly.Notices.delete('webhook')
        except Exception as e:
            self._webhook_id = None
            LOGGER.warning(f'Webhook registration failed: {e}')
            self.poly.Notices['webhook'] = f'Doorbell webhook not registered: {e}'

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _reset_driver(self, node, driver: str, delay: float = 3.0):
        await asyncio.sleep(delay)
        node.setDriver(driver, 0, report=True, force=False)

    def _save_and_rebuild_profile(self):
        self._users.save()
        write_profile(self._users, self._groups, self._policies)
        try:
            self.poly.updateProfile()
        except Exception as e:
            LOGGER.warning(f'updateProfile failed: {e}')

    # ------------------------------------------------------------------
    # Unlock
    # ------------------------------------------------------------------

    def unlock_door(self, door_id: str):
        if self._client:
            self._async.submit(self._do_unlock(door_id), 'unlock door')
        else:
            # Never fail an unlock silently — this is a door.
            LOGGER.error(f'Cannot unlock {door_id}: no connection to UniFi Access')

    async def _do_unlock(self, door_id: str):
        try:
            await self._client.unlock_door(door_id)
            LOGGER.info(f'Unlocked door {door_id}')
            door = self._door_by_id.get(door_id)
            if door:
                door.set_locked('unlock')
        except Exception as e:
            LOGGER.error(f'Unlock failed for {door_id}: {e}')

    # ------------------------------------------------------------------
    # Poll
    # ------------------------------------------------------------------

    def poll(self, flag):
        # Safety net for the case the supervisor never started at all: a
        # startup callback that didn't fire, a crashed handler thread, or
        # params that arrived late. shortPoll (60s) rather than longPoll so
        # recovery is a minute, not ten.
        if flag == 'shortPoll':
            if not self._initialized and self._is_configured():
                LOGGER.warning('No connection supervisor running — starting one')
                self._try_connect()
            return
        if flag == 'longPoll' and self._initialized and self._client:
            self._async.submit(self._fetch_and_discover(), 'longPoll discover')

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def query(self, command=None):
        self.reportDrivers()
        for node in itertools.chain(self._doors.values(), self._readers.values()):
            node.query()

    def cmd_discover(self, command=None):
        if not self._initialized:
            self._try_connect()
        elif self._client:
            self._async.submit(self._fetch_and_discover(), 'manual discover')

    def cmd_set_grp_policy(self, command):
        group_idx  = _cmd_param(command, 'group',  25)
        policy_idx = _cmd_param(command, 'policy', 25)
        if group_idx < 0 or group_idx >= len(self._groups):
            LOGGER.warning(f'Invalid group index: {group_idx}')
            return
        if policy_idx < 0 or policy_idx >= len(self._policies):
            LOGGER.warning(f'Invalid policy index: {policy_idx}')
            return
        group  = self._groups[group_idx]
        policy = self._policies[policy_idx]
        LOGGER.info(f'Setting group "{group["name"]}" → policy "{policy["name"]}"')
        self._async.submit(
            self._do_set_group_policy(group['id'], policy['id']), 'set group policy')

    async def _do_set_group_policy(self, group_id: str, policy_id: str):
        try:
            await self._client.set_group_policies(group_id, [policy_id])
            LOGGER.info(f'Group policy set successfully')
        except Exception as e:
            LOGGER.error(f'Failed to set group policy: {e}')

    def cmd_set_usr_policy(self, command):
        user_idx   = _cmd_param(command, 'user',   56)
        policy_idx = _cmd_param(command, 'policy', 25)
        user_uuid = self._users.get_uuid(user_idx)
        if not user_uuid:
            LOGGER.warning(f'No UUID for user index {user_idx}')
            return
        if policy_idx < 0 or policy_idx >= len(self._policies):
            LOGGER.warning(f'Invalid policy index: {policy_idx}')
            return
        policy = self._policies[policy_idx]
        user_name = self._users._num_to_name.get(user_idx, user_idx)
        LOGGER.info(f'Setting user "{user_name}" → policy "{policy["name"]}"')
        self._async.submit(
            self._do_set_user_policy(user_uuid, policy['id']), 'set user policy')

    async def _do_set_user_policy(self, user_id: str, policy_id: str):
        try:
            await self._client.set_user_policies(user_id, [policy_id])
            LOGGER.info(f'User policy set successfully')
        except Exception as e:
            LOGGER.error(f'Failed to set user policy: {e}')

    commands = {
        'QUERY':          query,
        'DISCOVER':       cmd_discover,
        'SET_GRP_POLICY': cmd_set_grp_policy,
        'SET_USR_POLICY': cmd_set_usr_policy,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    polyglot = udi_interface.Interface([Controller, DoorNode, ReaderNode])
    polyglot.start('2.0.0')
    Controller(polyglot, 'controller', 'controller', 'UniFi Access')
    polyglot.runForever()
