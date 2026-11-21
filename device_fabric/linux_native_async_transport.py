"""Single-loop TLS transport for the YFC native worker."""
from __future__ import annotations

import asyncio
import concurrent.futures
import threading
from collections.abc import Callable


class _Connection:
    def __init__(self, connector: Callable, uri: str, kwargs: dict):
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        try:
            self._thread.start()
            self._socket = self._call(self._open(connector, uri, kwargs), 15)
        except BaseException:
            kwargs['sock'].close()
            if self._thread.ident is None:
                self._loop.close()
            else:
                self._stop()
            raise

    @staticmethod
    async def _open(connector: Callable, uri: str, kwargs: dict):
        kwargs['sock'].setblocking(False)
        return await connector(uri, **kwargs)

    def _call(self, coroutine, timeout: float):
        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        try:
            return future.result(timeout)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise TimeoutError('native_transport_timeout') from None

    async def _cancel_pending(self) -> None:
        pending = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        await self._loop.shutdown_asyncgens()

    def _stop(self) -> None:
        try:
            self._call(self._cancel_pending(), 5)
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(5)
            if self._thread.is_alive():
                raise RuntimeError('native_transport_stop_denied')
            self._loop.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        try:
            self._call(self._socket.close(), 5)
        finally:
            self._stop()

    def send(self, data: str) -> None:
        self._call(self._socket.send(data), 10)

    def recv(self, timeout: float):
        return self._call(asyncio.wait_for(self._socket.recv(), timeout), timeout + 1)


def sync_adapter(connector: Callable) -> Callable:
    """Expose the native synchronous interface without concurrent SSL calls."""
    if not callable(connector):
        raise ValueError('native_transport_denied')
    return lambda uri, **kwargs: _Connection(connector, uri, kwargs)
