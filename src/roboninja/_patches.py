"""Runtime patches applied by RoboNinja."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urljoin, urlparse

import anyio
import httpx
import mcp.client.sse as _sse_module
import mcp.types as types
from anyio.abc import TaskStatus
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from httpx_sse import aconnect_sse
from mcp.shared._httpx_utils import McpHttpClientFactory, create_mcp_http_client
from mcp.shared.message import SessionMessage

logger = logging.getLogger(__name__)

_PATCH_FLAG = "_roboninja_sse_patched"
_POST_TIMEOUT = 60.0


def _remove_request_params(url: str) -> str:
    return urljoin(url, urlparse(url).path)


@asynccontextmanager
async def _patched_sse_client(
    url: str,
    headers: dict[str, Any] | None = None,
    timeout: float = 5,
    sse_read_timeout: float = 60 * 5,
    httpx_client_factory: McpHttpClientFactory = create_mcp_http_client,
    auth: httpx.Auth | None = None,
):
    read_stream: MemoryObjectReceiveStream[SessionMessage | Exception]
    read_stream_writer: MemoryObjectSendStream[SessionMessage | Exception]

    write_stream: MemoryObjectSendStream[SessionMessage]
    write_stream_reader: MemoryObjectReceiveStream[SessionMessage]

    read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
    write_stream, write_stream_reader = anyio.create_memory_object_stream(0)

    async with anyio.create_task_group() as tg:
        try:
            logger.debug("Connecting to SSE endpoint: %s", _remove_request_params(url))
            async with httpx_client_factory(
                headers=headers, auth=auth, timeout=httpx.Timeout(timeout, read=sse_read_timeout)
            ) as client:
                async with aconnect_sse(client, "GET", url) as event_source:
                    event_source.response.raise_for_status()
                    logger.debug("SSE connection established")

                    async def sse_reader(
                        task_status: TaskStatus[str] = anyio.TASK_STATUS_IGNORED,
                    ):
                        try:
                            async for sse in event_source.aiter_sse():
                                logger.debug("Received SSE event: %s", sse.event)
                                match sse.event:
                                    case "endpoint":
                                        endpoint_url = urljoin(url, sse.data)
                                        logger.debug("Received endpoint URL: %s", endpoint_url)

                                        url_parsed = urlparse(url)
                                        endpoint_parsed = urlparse(endpoint_url)
                                        if (
                                            url_parsed.netloc != endpoint_parsed.netloc
                                            or url_parsed.scheme != endpoint_parsed.scheme
                                        ):
                                            error_msg = (
                                                "Endpoint origin does not match connection origin: "
                                                f"{endpoint_url}"
                                            )
                                            logger.error(error_msg)
                                            raise ValueError(error_msg)

                                        task_status.started(endpoint_url)

                                    case "message":
                                        try:
                                            message = types.JSONRPCMessage.model_validate_json(sse.data)
                                            logger.debug("Received server message: %s", message)
                                        except Exception as exc:  # pragma: no cover
                                            logger.exception("Error parsing server message")
                                            await read_stream_writer.send(exc)
                                            continue

                                        session_message = SessionMessage(message)
                                        await read_stream_writer.send(session_message)
                                    case _:
                                        logger.warning("Unknown SSE event: %s", sse.event)
                        except Exception as exc:
                            logger.exception("Error in sse_reader")
                            await read_stream_writer.send(exc)
                        finally:
                            await read_stream_writer.aclose()

                    async def post_writer(endpoint_url: str):
                        try:
                            async with write_stream_reader:
                                async for session_message in write_stream_reader:
                                    logger.debug("Sending client message: %s", session_message)
                                    try:
                                        async with anyio.fail_after(_POST_TIMEOUT):
                                            response = await client.post(
                                                endpoint_url,
                                                json=session_message.message.model_dump(
                                                    by_alias=True,
                                                    mode="json",
                                                    exclude_none=True,
                                                ),
                                            )
                                        response.raise_for_status()
                                        logger.debug(
                                            "Client message sent successfully: %s",
                                            response.status_code,
                                        )
                                    except Exception as exc:
                                        logger.exception("Error in post_writer")
                                        await read_stream_writer.send(exc)
                                        break
                        finally:
                            await write_stream.aclose()

                    endpoint_url = await tg.start(sse_reader)
                    logger.debug("Starting post writer with endpoint URL: %s", endpoint_url)
                    tg.start_soon(post_writer, endpoint_url)

                    try:
                        yield read_stream, write_stream
                    finally:
                        tg.cancel_scope.cancel()
        finally:
            await read_stream_writer.aclose()
            await write_stream.aclose()


def apply_patches() -> None:
    """Apply RoboNinja runtime patches exactly once."""

    if getattr(_sse_module, _PATCH_FLAG, False):
        return

    setattr(_sse_module, "sse_client", _patched_sse_client)
    setattr(_sse_module, _PATCH_FLAG, True)
    logger.debug("Applied RoboNinja SSE client patches")
