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
import json
import os
import ssl
import threading

import aiohttp
import udi_interface

LOGGER = udi_interface.LOGGER

# ---------------------------------------------------------------------------
# API constants
# ---------------------------------------------------------------------------

_API_BASE    = '/api/v1/developer'
_DOORS_URL   = _API_BASE + '/doors'
_DEVICES_URL = _API_BASE + '/devices'
_WS_URL      = _API_BASE + '/devices/notifications'

_EVT_LOCATION_UPDATE = 'access.data.device.location_update_v2'
_EVT_V2_LOCATION     = 'access.data.v2.location.update'
_EVT_LOG_ADD         = 'access.logs.insights.add'
_EVT_DOORBELL        = 'access.hw.door_bell'

_MAX_USERS = 30

_AUTH_METHOD_MAP = {
    'nfc': 1, 'card': 1, 'rfid': 1,
    'pin': 2, 'keypad': 2, 'code': 2,
    'face': 3, 'fingerprint': 3,
    'mobile': 4, 'bluetooth': 4, 'app': 4,
}

_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
_NLS_PATH    = os.path.join(_SCRIPT_DIR, 'profile', 'nls', 'en_us.txt')
_USER_MAP_FILE = os.path.join(_SCRIPT_DIR, 'usermap.json')

# ---------------------------------------------------------------------------
# User map
# ---------------------------------------------------------------------------

class UserMap:
    """Persistent mapping of Access user UUIDs to stable ISY numeric indices.

    Users pre-configured via comma-list in custom params get numbers first.
    Unknown users are auto-learned from auth events.
    """

    def __init__(self):
        self._uuid_to_num  = {}         # uuid  → int
        self._name_to_num  = {}         # name.lower() → int
        self._num_to_name  = {0: 'Unknown'}
        self._next         = 1
        self.changed       = False

    def load(self):
        if not os.path.exists(_USER_MAP_FILE):
            return
        try:
            with open(_USER_MAP_FILE) as f:
                data = json.load(f)
            for uid, entry in data.get('by_id', {}).items():
                num, name = entry['num'], entry['name']
                self._uuid_to_num[uid]         = num
                self._name_to_num[name.lower()] = num
                self._num_to_name[num]          = name
                if num >= self._next:
                    self._next = num + 1
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

    def seed_from_config(self, users_csv: str):
        """Pre-populate from comma-separated names in custom params."""
        changed = False
        for name in [n.strip() for n in users_csv.split(',') if n.strip()]:
            key = name.lower()
            if key not in self._name_to_num:
                num = self._next
                self._next += 1
                sentinel = f'__config__{key}'
                self._uuid_to_num[sentinel]  = num
                self._name_to_num[key]       = num
                self._num_to_name[num]       = name
                changed = True
                LOGGER.info(f'Pre-configured user: {name} → {num}')
        if changed:
            self.changed = True

    def get_or_add(self, uid: str, display_name: str) -> int:
        """Return numeric index for this user, adding if new. 0 = unknown."""
        # Lookup by UUID
        if uid and uid in self._uuid_to_num:
            num = self._uuid_to_num[uid]
            # Update name if we now have a better one
            if display_name and self._num_to_name.get(num) != display_name:
                self._num_to_name[num]               = display_name
                self._name_to_num[display_name.lower()] = num
                self.changed = True
            return num

        # Lookup by name (matches pre-configured entries)
        if display_name:
            key = display_name.lower()
            if key in self._name_to_num:
                num = self._name_to_num[key]
                if uid:
                    self._uuid_to_num[uid] = num
                    self.changed = True
                return num

        # Auto-learn new user
        if not display_name or self._next > _MAX_USERS:
            return 0

        num      = self._next
        self._next += 1
        key_uid  = uid or f'__auto_{num}__'
        self._uuid_to_num[key_uid]                      = num
        self._name_to_num[display_name.lower()]         = num
        self._num_to_name[num]                          = display_name
        self.changed = True
        LOGGER.info(f'Auto-learned user: {display_name} → {num}')
        return num

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

# Auth Method values (GV2)
AUTH_METHOD-0 = Unknown
AUTH_METHOD-1 = NFC / Card
AUTH_METHOD-2 = PIN
AUTH_METHOD-3 = Face ID
AUTH_METHOD-4 = Mobile

# Users (GV1) — generated dynamically
"""


def write_nls(user_map: UserMap):
    try:
        with open(_NLS_PATH, 'w') as f:
            f.write(_NLS_BASE)
            for line in user_map.nls_lines():
                f.write(line + '\n')
    except Exception as e:
        LOGGER.error(f'Failed to write NLS: {e}')


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
        self._session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))

    async def get_doors(self) -> list:
        resp = await self._session.get(self._url(_DOORS_URL),
                                       headers=self._headers(), ssl=self._ssl)
        resp.raise_for_status()
        return (await resp.json()).get('data') or []

    async def get_devices(self) -> list:
        resp = await self._session.get(self._url(_DEVICES_URL),
                                       headers=self._headers(), ssl=self._ssl)
        resp.raise_for_status()
        raw = (await resp.json()).get('data') or []
        # API returns nested arrays: [[device,...], [device,...], ...]
        devices = []
        for group in raw:
            if isinstance(group, list):
                devices.extend(group)
            elif isinstance(group, dict):
                devices.append(group)
        return devices

    async def unlock_door(self, door_id):
        resp = await self._session.put(
            self._url(f'{_DOORS_URL}/{door_id}/unlock'),
            headers=self._headers(), ssl=self._ssl)
        resp.raise_for_status()

    async def listen(self, on_message):
        async with self._session.ws_connect(
                self._ws_url(), headers=self._headers(),
                ssl=self._ssl, heartbeat=30) as ws:
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
                    on_message(event, payload.get('data', {}))
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    LOGGER.warning(f'WebSocket {msg.type}')
                    break

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

    def submit(self, coro):
        asyncio.run_coroutine_threadsafe(coro, self._loop)

    def shutdown(self):
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)


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
        self.device_id   = device_id
        self._door_id    = None   # resolved after creation

    def ring(self):
        self.setDriver('ST', 1, report=True, force=True)

    def set_user(self, num: int):
        self.setDriver('GV1', num, report=True, force=True)

    def set_auth_method(self, method: str):
        val = 0
        m = method.lower()
        for key, num in _AUTH_METHOD_MAP.items():
            if key in m:
                val = num
                break
        self.setDriver('GV2', val, report=True, force=True)

    def granted(self):
        self.setDriver('GV3', 1, report=True, force=True)

    def denied(self):
        self.setDriver('GV4', 1, report=True, force=True)

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

    def __init__(self, polyglot, primary, address, name, door_id):
        super().__init__(polyglot, primary, address, name)
        self.door_id     = door_id
        self._controller = None

    def set_position(self, status: str):
        self.setDriver('ST', 1 if status == 'open' else 0, report=True, force=False)

    def set_locked(self, status: str):
        locked = status in ('lock', 'locked')
        self.setDriver('GV1', 1 if locked else 0, report=True, force=False)

    def query(self, command=None):
        self.reportDrivers()

    def cmd_unlock(self, command=None):
        if self._controller:
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

        self._async            = _AsyncBridge()
        self._client           = None
        self._doors            = {}    # door_address → DoorNode
        self._readers          = {}    # reader_address → ReaderNode
        self._reader_by_dev    = {}    # device_id → ReaderNode
        self._initialized      = False
        self._controller_added = False
        self._node_added       = threading.Event()
        self._params           = udi_interface.Custom(polyglot, 'customparams')
        self._users            = UserMap()

        polyglot.subscribe(polyglot.CONFIGDONE,   self._on_config_done)
        polyglot.subscribe(polyglot.START,        self.start)
        polyglot.subscribe(polyglot.CUSTOMPARAMS, self.param_handler)
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

    def stop(self):
        LOGGER.info('Stopping UniFi Access nodeserver')
        if self._client:
            self._async.run(self._client.close(), timeout=10)
        self._async.shutdown()

    def _on_config_done(self):
        if self._controller_added:
            return
        try:
            self._add_node_wait(self, timeout=3)
            self._controller_added = True
            self.setDriver('ST', 1)
            if not self._initialized:
                self._try_connect()
        except Exception as e:
            LOGGER.error(f'Failed to add controller node: {e}', exc_info=True)

    def _on_node_added(self, data):
        self._node_added.set()

    def _add_node_wait(self, node, timeout=15):
        self._node_added.clear()
        self.poly.addNode(node)
        self._node_added.wait(timeout=timeout)

    # ------------------------------------------------------------------
    # Params / connection
    # ------------------------------------------------------------------

    def param_handler(self, params):
        self._params.load(params)
        self.poly.Notices.clear()

        host      = params.get('host',      '').strip()
        api_token = params.get('api_token', '').strip()

        if not host or not api_token:
            self.poly.Notices['config'] = 'Set host and api_token in Custom Parameters'
            return

        if not self._initialized:
            self._try_connect()

    def _try_connect(self):
        params    = self._params
        host      = (params.get('host')      or '').strip()
        api_token = (params.get('api_token') or '').strip()
        port      = int((params.get('port')  or '12445').strip())
        verify    = (params.get('verify_ssl') or 'false').strip().lower() == 'true'
        users_csv = (params.get('users')     or '').strip()

        if not host or not api_token:
            return

        # Load user map and seed from config before connecting
        self._users.load()
        if users_csv:
            self._users.seed_from_config(users_csv)
        self._rebuild_profile()

        self._initialized = True
        self._async.submit(self._connect(host, port, api_token, verify))

    async def _connect(self, host, port, api_token, verify_ssl):
        try:
            LOGGER.info(f'Connecting to UniFi Access at {host}:{port}')
            self._client = AccessClient(host, port, api_token, verify_ssl)
            await self._client.connect()

            doors   = await self._client.get_doors()
            devices = await self._client.get_devices()
            LOGGER.info(f'Discovered {len(doors)} door(s), {len(devices)} device(s)')
            self._discover(doors, devices)

            LOGGER.info('Listening for WebSocket events')
            await self._ws_loop()

        except Exception as e:
            LOGGER.error(f'Connection failed: {e}', exc_info=True)
            self.poly.Notices['error'] = f'Connection failed: {e}'
            self._initialized = False
            if self._client:
                await self._client.close()
                self._client = None

    async def _ws_loop(self):
        backoff = 5
        while self._initialized:
            try:
                self.setDriver('ST', 1)
                await self._client.listen(self._on_ws_message)
            except Exception as e:
                LOGGER.warning(f'WebSocket disconnected: {e} — reconnecting in {backoff}s')
            self.setDriver('ST', 0)
            if not self._initialized:
                break
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)
            try:
                await self._client.reconnect()
                doors   = await self._client.get_doors()
                devices = await self._client.get_devices()
                self._discover(doors, devices)
                backoff = 5
            except Exception as e:
                LOGGER.warning(f'Reconnect failed: {e}')

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _discover(self, doors: list, devices: list):
        # Step 1: ensure door nodes
        door_id_to_addr = {}
        for door in doors:
            node = self._ensure_door(door)
            if node:
                door_id_to_addr[door['id']] = node.address

        # Step 2: build hub→door map (hub.location_id == door_id)
        hub_to_door = {}   # hub device_id → door_id
        for dev in devices:
            caps = dev.get('capabilities', [])
            if 'is_hub' in caps:
                loc = dev.get('location_id', '')
                if loc in door_id_to_addr:
                    hub_to_door[dev['id']] = loc

        # Step 3: ensure reader nodes, linking to doors
        for dev in devices:
            caps = dev.get('capabilities', [])
            if 'is_reader' not in caps:
                continue

            # Resolve which door this reader belongs to
            door_id = None
            loc = dev.get('location_id', '')

            # Direct match: reader's location_id is a door_id
            if loc in door_id_to_addr:
                door_id = loc
            # Hub match: reader is at same location as a hub that's at a door
            else:
                for hub_id, hdoor_id in hub_to_door.items():
                    # Check if reader is at the hub's location
                    hub_loc = next((d.get('location_id')
                                    for d in devices if d.get('id') == hub_id), None)
                    if hub_loc == loc:
                        door_id = hdoor_id
                        break

            # Fallback: single door setup
            if not door_id and len(door_id_to_addr) == 1:
                door_id = next(iter(door_id_to_addr))

            door_addr = door_id_to_addr.get(door_id) if door_id else self.address
            self._ensure_reader(dev, door_addr)

    def _ensure_door(self, door: dict):
        door_id = door.get('id', '')
        if not door_id:
            return None
        address = door_id[:14].lower().replace('-', '')
        if address in self._doors:
            node = self._doors[address]
            node.set_position(door.get('door_position_status', 'none'))
            node.set_locked(door.get('door_lock_relay_status', 'lock'))
            return node
        name = door.get('name') or door_id
        node = DoorNode(self.poly, self.address, address, name, door_id)
        node._controller = self
        self._add_node_wait(node, timeout=3)
        node.set_position(door.get('door_position_status', 'none'))
        node.set_locked(door.get('door_lock_relay_status', 'lock'))
        self._doors[address] = node
        LOGGER.info(f'Added door: {name} ({address})')
        return node

    def _ensure_reader(self, dev: dict, primary_address: str):
        dev_id  = dev.get('id', '')
        if not dev_id:
            return None
        address = dev_id[:14].lower()
        if address in self._readers:
            return self._readers[address]
        name = dev.get('alias') or dev.get('name') or dev_id
        node = ReaderNode(self.poly, primary_address, address, name, dev_id)
        self._add_node_wait(node, timeout=3)
        self._readers[address]        = node
        self._reader_by_dev[dev_id]   = node
        LOGGER.info(f'Added reader: {name} ({address}) under {primary_address}')
        return node

    # ------------------------------------------------------------------
    # WebSocket event handling
    # ------------------------------------------------------------------

    def _on_ws_message(self, event: str, data: dict):
        try:
            if event in (_EVT_LOCATION_UPDATE, _EVT_V2_LOCATION):
                self._handle_location_update(data)
            elif event == _EVT_LOG_ADD:
                self._handle_log_event(data)
            elif event == _EVT_DOORBELL:
                self._handle_doorbell(data)
        except Exception as e:
            LOGGER.error(f'WS message error: {e}', exc_info=True)

    def _handle_location_update(self, data: dict):
        door_id = data.get('id', '')
        door    = self._door_for_id(door_id)
        if not door:
            return
        state = data.get('state', {})
        if state.get('dps'):
            door.set_position(state['dps'])
        if state.get('lock'):
            door.set_locked(state['lock'])

    def _handle_doorbell(self, data: dict):
        dev_id = (data.get('device_id') or data.get('deviceId')
                  or data.get('id') or '')
        reader = self._reader_by_dev.get(dev_id)
        if reader:
            reader.ring()
            self._async.submit(self._reset_driver(reader, 'ST'))
            LOGGER.info(f'Doorbell ring: {reader.name}')
        else:
            LOGGER.info(f'Doorbell from unknown device: {dev_id} — data: {data}')

    def _handle_log_event(self, data: dict):
        source  = data.get('source', {})
        result  = (source.get('event') or {}).get('result', '')
        granted = 'GRANTED' in result

        actor  = source.get('actor') or {}
        uid    = actor.get('id', '')
        name   = actor.get('display_name') or actor.get('name') or ''
        auth   = source.get('authentication') or {}
        method = auth.get('credential_provider') or auth.get('type') or ''

        # Resolve user number (auto-learn if new)
        user_num = self._users.get_or_add(uid, name)
        if self._users.changed:
            self._users.save()
            self._rebuild_profile()

        status = 'GRANTED' if granted else 'DENIED'
        LOGGER.info(f'Access {status}: {name or uid} via {method or "?"}'
                    f' (user={user_num})')

        # Find which reader triggered this (device in source targets)
        reader = self._reader_from_source(source)

        # Find which door(s) this event targets
        for target in (source.get('target') or []):
            if target.get('type') != 'door':
                continue
            door = self._door_for_id(target.get('id', ''))
            if not door:
                continue

            # If we don't have a reader, look for one under this door
            if not reader:
                reader = self._reader_under_door(door)

            if reader:
                reader.set_user(user_num)
                reader.set_auth_method(method)
                if granted:
                    reader.granted()
                    self._async.submit(self._reset_driver(reader, 'GV3'))
                else:
                    reader.denied()
                    self._async.submit(self._reset_driver(reader, 'GV4'))

    def _reader_from_source(self, source: dict):
        """Try to identify which reader device generated this event."""
        # Some firmware versions include device info in the source
        dev_id = (source.get('device_id') or source.get('deviceId') or
                  (source.get('device') or {}).get('id') or '')
        return self._reader_by_dev.get(dev_id)

    def _reader_under_door(self, door: DoorNode):
        """Return the first reader whose primary is this door."""
        for r in self._readers.values():
            if r.primary == door.address:
                return r
        return None

    # ------------------------------------------------------------------
    # Profile / NLS management
    # ------------------------------------------------------------------

    def _rebuild_profile(self):
        write_nls(self._users)
        try:
            self.poly.updateProfile()
            LOGGER.info('Profile updated')
        except Exception as e:
            LOGGER.warning(f'updateProfile failed: {e}')

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _door_for_id(self, door_id: str):
        for node in self._doors.values():
            if node.door_id == door_id:
                return node
        return None

    async def _reset_driver(self, node, driver: str, delay: float = 3.0):
        await asyncio.sleep(delay)
        node.setDriver(driver, 0, report=True, force=False)

    # ------------------------------------------------------------------
    # Unlock (called from DoorNode)
    # ------------------------------------------------------------------

    def unlock_door(self, door_id: str):
        if self._client:
            self._async.submit(self._do_unlock(door_id))

    async def _do_unlock(self, door_id: str):
        try:
            await self._client.unlock_door(door_id)
            LOGGER.info(f'Unlocked door {door_id}')
            door = self._door_for_id(door_id)
            if door:
                door.set_locked('unlock')
        except Exception as e:
            LOGGER.error(f'Unlock failed for {door_id}: {e}')

    # ------------------------------------------------------------------
    # Poll
    # ------------------------------------------------------------------

    def poll(self, flag):
        if not self._initialized or not self._client:
            return
        if flag == 'longPoll':
            self._async.submit(self._resync())

    async def _resync(self):
        try:
            doors   = await self._client.get_doors()
            devices = await self._client.get_devices()
            self._discover(doors, devices)
        except Exception as e:
            LOGGER.warning(f'Resync failed: {e}')

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def query(self, command=None):
        self.reportDrivers()
        for n in list(self._doors.values()) + list(self._readers.values()):
            n.query()

    def cmd_discover(self, command=None):
        if not self._initialized:
            self._try_connect()
        elif self._client:
            self._async.submit(self._resync())

    commands = {'QUERY': query, 'DISCOVER': cmd_discover}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    polyglot = udi_interface.Interface([])
    polyglot.start('2.0.0')
    Controller(polyglot, 'controller', 'controller', 'UniFi Access')
    polyglot.runForever()
