#!/usr/bin/env python3
"""UniFi Access nodeserver for ISY/PG3x.

Each door becomes a node with drivers for position (open/closed),
lock status (locked/unlocked), and last access result (granted/denied).
Doors can be unlocked via ISY commands/programs.

Uses the UniFi Access Developer API (port 12445) with an API token —
no username/password required.
"""

import asyncio
import json
import logging
import ssl
import threading

import aiohttp
import udi_interface

LOGGER = udi_interface.LOGGER

# ---------------------------------------------------------------------------
# UniFi Access Developer API client
# ---------------------------------------------------------------------------

_API_BASE  = '/api/v1/developer'
_DOORS_URL = _API_BASE + '/doors'
_WS_URL    = _API_BASE + '/devices/notifications'

# WebSocket event topics
_EVT_LOCATION_UPDATE = 'access.data.device.location_update_v2'
_EVT_V2_LOCATION     = 'access.data.v2.location.update'
_EVT_LOG_ADD         = 'access.logs.insights.add'
_EVT_DOORBELL        = 'access.hw.door_bell'


class AccessClient:
    """Minimal aiohttp-based UniFi Access developer API client."""

    def __init__(self, host: str, port: int, api_token: str,
                 verify_ssl: bool = False):
        self.host      = host
        self.port      = port
        self.api_token = api_token
        self._ssl      = ssl.create_default_context() if verify_ssl else False
        self._session  = None

    def _url(self, path: str) -> str:
        return f'https://{self.host}:{self.port}{path}'

    def _ws_url(self) -> str:
        return f'wss://{self.host}:{self.port}{_WS_URL}'

    def _headers(self) -> dict:
        return {'Authorization': f'Bearer {self.api_token}'}

    async def connect(self):
        jar = aiohttp.CookieJar(unsafe=True)
        self._session = aiohttp.ClientSession(cookie_jar=jar)

    async def get_doors(self) -> list:
        resp = await self._session.get(
            self._url(_DOORS_URL),
            headers=self._headers(),
            ssl=self._ssl,
        )
        resp.raise_for_status()
        result = await resp.json()
        # API returns {"data": [...], "code": "SUCCESS"}
        return result.get('data') or []

    async def unlock_door(self, door_id: str):
        resp = await self._session.put(
            self._url(f'{_DOORS_URL}/{door_id}/unlock'),
            headers=self._headers(),
            ssl=self._ssl,
        )
        resp.raise_for_status()

    async def listen(self, on_message):
        """Open WebSocket and call on_message(event, data) for each event."""
        async with self._session.ws_connect(
            self._ws_url(),
            headers=self._headers(),
            ssl=self._ssl,
            heartbeat=30,
        ) as ws:
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
                    data = payload.get('data', {})
                    on_message(event, data)
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    LOGGER.warning(f'WebSocket closed/error: {msg.type}')
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
        self._thread = threading.Thread(
            target=self._loop.run_forever, daemon=True, name='unifiaccess-async')
        self._thread.start()

    def run(self, coro, timeout=30):
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=timeout)
        except asyncio.TimeoutError:
            LOGGER.error('Async call timed out')
            return None
        except Exception as e:
            LOGGER.error(f'Async error: {e}')
            return None

    def submit(self, coro):
        asyncio.run_coroutine_threadsafe(coro, self._loop)

    def shutdown(self):
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Door node
# ---------------------------------------------------------------------------

class DoorNode(udi_interface.Node):
    id = 'access_door'

    drivers = [
        {'driver': 'ST',  'value': 0, 'uom': 2},  # door position: open=1 closed=0
        {'driver': 'GV1', 'value': 1, 'uom': 2},  # lock status: locked=1 unlocked=0
        {'driver': 'GV2', 'value': 0, 'uom': 2},  # last access: granted=1 denied=0
    ]

    def __init__(self, polyglot, primary, address, name, door_id):
        super().__init__(polyglot, primary, address, name)
        self.door_id = door_id
        self._controller = None  # set by Controller after creation

    def _set(self, driver, value):
        self.setDriver(driver, 1 if value else 0, report=True, force=False)

    def set_position(self, status: str):
        """status: 'open', 'close', or 'none'"""
        self._set('ST', status == 'open')

    def set_locked(self, status: str):
        """status: 'lock'/'locked' = 1, 'unlock'/'unlocked' = 0"""
        self._set('GV1', status in ('lock', 'locked'))

    def set_access_result(self, granted: bool):
        self._set('GV2', granted)

    def query(self, command=None):
        self.reportDrivers()

    def cmd_unlock(self, command=None):
        if self._controller:
            self._controller.unlock_door(self.door_id)

    commands = {
        'QUERY':  query,
        'UNLOCK': cmd_unlock,
    }


# ---------------------------------------------------------------------------
# Controller node
# ---------------------------------------------------------------------------

class Controller(udi_interface.Node):
    id = 'access_controller'

    drivers = [
        {'driver': 'ST', 'value': 0, 'uom': 2},
    ]

    def __init__(self, polyglot, primary, address, name):
        super().__init__(polyglot, primary, address, name)

        self._async            = _AsyncBridge()
        self._client           = None
        self._doors            = {}     # address -> DoorNode
        self._initialized      = False
        self._controller_added = False
        self._node_added       = threading.Event()
        self._params           = udi_interface.Custom(polyglot, 'customparams')

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
        LOGGER.debug('start() called')

    def stop(self):
        LOGGER.info('Stopping UniFi Access nodeserver')
        if self._client:
            self._async.run(self._client.close(), timeout=10)
        self._async.shutdown()

    def _on_config_done(self):
        if self._controller_added:
            return
        LOGGER.info('Config done — adding controller node')
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
            self.poly.Notices['config'] = (
                'Set host and api_token in Custom Parameters')
            return

        if not self._initialized:
            self._try_connect()

    def _try_connect(self):
        params    = self._params
        host      = (params.get('host')      or '').strip()
        api_token = (params.get('api_token') or '').strip()
        port      = int((params.get('port')  or '12445').strip())
        verify    = (params.get('verify_ssl') or 'false').strip().lower() == 'true'

        if not host or not api_token:
            return

        self._initialized = True
        self._async.submit(self._connect(host, port, api_token, verify))

    async def _connect(self, host, port, api_token, verify_ssl):
        try:
            LOGGER.info(f'Connecting to UniFi Access at {host}:{port}')
            self._client = AccessClient(host, port, api_token, verify_ssl)
            await self._client.connect()

            doors = await self._client.get_doors()
            LOGGER.info(f'Discovered {len(doors)} door(s)')
            self._discover_doors(doors)

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
        """WebSocket listener with automatic reconnection."""
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
                doors = await self._client.get_doors()
                self._discover_doors(doors)
                backoff = 5
            except Exception as e:
                LOGGER.warning(f'Reconnect failed: {e}')

    # ------------------------------------------------------------------
    # Door discovery
    # ------------------------------------------------------------------

    def _discover_doors(self, doors: list):
        for door in doors:
            self._ensure_door(door)

    def _ensure_door(self, door: dict):
        door_id = door.get('id', '')
        if not door_id:
            return None

        # Use door ID (truncated) as address — stable logical entity in Access
        address = door_id[:14].lower().replace('-', '')
        if address in self._doors:
            node = self._doors[address]
            # Refresh state from poll data
            node.set_position(door.get('door_position_status', 'none'))
            node.set_locked(door.get('door_lock_relay_status', 'lock'))
            return node

        name = door.get('name') or door.get('full_name') or door_id
        node = DoorNode(self.poly, self.address, address, name, door_id)
        node._controller = self
        self._add_node_wait(node, timeout=3)
        node.set_position(door.get('door_position_status', 'none'))
        node.set_locked(door.get('door_lock_relay_status', 'lock'))
        self._doors[address] = node
        LOGGER.info(f'Added door: {name} ({address})')
        return node

    def _node_for_door(self, door_id: str):
        for node in self._doors.values():
            if node.door_id == door_id:
                return node
        return None

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
                door_id = data.get('door_id') or data.get('doorId', '')
                LOGGER.info(f'Doorbell: door {door_id}')
        except Exception as e:
            LOGGER.error(f'Error handling WS message: {e}', exc_info=True)

    def _handle_location_update(self, data: dict):
        door_id = data.get('id', '')
        node    = self._node_for_door(door_id)
        if not node:
            return
        state = data.get('state', {})
        dps   = state.get('dps', '')
        lock  = state.get('lock', '')
        if dps:
            node.set_position(dps)
        if lock:
            node.set_locked(lock)

    def _handle_log_event(self, data: dict):
        # data.source.event.result: ACCESS_GRANTED / ACCESS_DENIED / BLOCKED
        source = data.get('source', {})
        result = (source.get('event') or {}).get('result', '')
        granted = 'GRANTED' in result

        # Find which door(s) this event targets
        targets = source.get('target', [])
        for target in targets:
            if target.get('type') == 'door':
                node = self._node_for_door(target.get('id', ''))
                if node:
                    node.set_access_result(granted)
                    # Pulse: reset after 3s so every auth fires a fresh ISY trigger
                    self._async.submit(self._reset_access_result(node))

    async def _reset_access_result(self, node):
        await asyncio.sleep(3)
        node.set_access_result(False)

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
            node = self._node_for_door(door_id)
            if node:
                node.set_locked(False)
        except Exception as e:
            LOGGER.error(f'Failed to unlock door {door_id}: {e}')

    # ------------------------------------------------------------------
    # Poll — re-sync door state
    # ------------------------------------------------------------------

    def poll(self, flag):
        if not self._initialized or not self._client:
            return
        if flag == 'longPoll':
            self._async.submit(self._resync())

    async def _resync(self):
        try:
            doors = await self._client.get_doors()
            self._discover_doors(doors)
        except Exception as e:
            LOGGER.warning(f'Resync failed: {e}')

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def query(self, command=None):
        self.reportDrivers()
        for node in self._doors.values():
            node.query()

    def cmd_discover(self, command=None):
        if not self._initialized:
            self._try_connect()
        elif self._client:
            self._async.submit(self._resync())

    commands = {
        'QUERY':    query,
        'DISCOVER': cmd_discover,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    polyglot = udi_interface.Interface([])
    polyglot.start('1.0.0')
    Controller(polyglot, 'controller', 'controller', 'UniFi Access')
    polyglot.runForever()
