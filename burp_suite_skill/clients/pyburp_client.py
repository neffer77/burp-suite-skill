"""
PyBurp gRPC client for Burp Suite.

Provides a Python interface to the PyBurp extension's gRPC server,
enabling low-level request manipulation and traffic modification
via the Montoya API bridge.
"""

import logging
from typing import Any

from burp_suite_skill.config import PYBURP_HOST, PYBURP_PORT, PYBURP_TIMEOUT

logger = logging.getLogger(__name__)


class PyBurpClientError(Exception):
    """Raised when a PyBurp gRPC call fails."""


class PyBurpClient:
    """
    gRPC client for the PyBurp Burp Suite extension.

    This client communicates with the PyBurp extension over gRPC,
    enabling fine-grained HTTP request manipulation, sending custom
    requests, and interacting with the Montoya API from Python.

    If gRPC dependencies (grpcio) are not available, the client will
    operate in a degraded mode and raise clear error messages.
    """

    def __init__(
        self,
        host: str = PYBURP_HOST,
        port: int = PYBURP_PORT,
        timeout: int = PYBURP_TIMEOUT,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._channel = None
        self._stub = None

    def _ensure_connected(self) -> None:
        """Establish the gRPC channel if not already connected."""
        if self._channel is not None:
            return
        try:
            import grpc
        except ImportError:
            raise PyBurpClientError(
                "grpcio is not installed. Install it with: pip install grpcio"
            )
        target = f"{self.host}:{self.port}"
        logger.info("Connecting to PyBurp gRPC at %s", target)
        self._channel = grpc.insecure_channel(target)
        # The stub will be created from PyBurp's proto definitions.
        # For now, we use a generic approach via channel.unary_unary.
        # When proto stubs are available, replace with the generated stub.

    def close(self) -> None:
        """Close the gRPC channel."""
        if self._channel is not None:
            self._channel.close()
            self._channel = None
            self._stub = None

    def send_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> dict[str, Any]:
        """
        Send an HTTP request through Burp Suite via PyBurp.

        This routes the request through Burp's HTTP engine, ensuring
        TLS handling, HTTP/2, and proxy settings are all applied.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.).
            url: Full URL to request.
            headers: Optional dict of HTTP headers.
            body: Optional request body string.

        Returns:
            Dict with keys: status_code, headers, body, time_ms.
        """
        self._ensure_connected()
        logger.info("Sending request via PyBurp: %s %s", method, url)

        # Build the request payload for the gRPC call
        request_data = {
            "method": method,
            "url": url,
            "headers": headers or {},
            "body": body or "",
        }

        try:
            # Use gRPC dynamic invocation. When proto stubs are compiled,
            # this will be replaced with: self._stub.SendRequest(request_msg)
            import grpc

            # Attempt to call the PyBurp service
            # PyBurp's proto defines a service with SendRequest RPC
            channel_method = self._channel.unary_unary(
                "/pyburp.PyBurpService/SendRequest",
                request_serializer=self._serialize_request,
                response_deserializer=self._deserialize_response,
            )
            response = channel_method(
                request_data,
                timeout=self.timeout,
            )
            return response

        except Exception as exc:
            raise PyBurpClientError(
                f"gRPC call to PyBurp failed: {exc}"
            ) from exc

    def send_raw_request(
        self,
        raw_request: str,
        host: str,
        port: int = 443,
        use_tls: bool = True,
    ) -> dict[str, Any]:
        """
        Send a raw HTTP request string through Burp Suite via PyBurp.

        Args:
            raw_request: Complete HTTP request as a string.
            host: Target hostname.
            port: Target port (default 443).
            use_tls: Whether to use TLS (default True).

        Returns:
            Dict with keys: status_code, headers, body, time_ms.
        """
        self._ensure_connected()
        logger.info("Sending raw request via PyBurp to %s:%d", host, port)

        request_data = {
            "raw_request": raw_request,
            "host": host,
            "port": port,
            "use_tls": use_tls,
        }

        try:
            import grpc

            channel_method = self._channel.unary_unary(
                "/pyburp.PyBurpService/SendRawRequest",
                request_serializer=self._serialize_request,
                response_deserializer=self._deserialize_response,
            )
            response = channel_method(
                request_data,
                timeout=self.timeout,
            )
            return response

        except Exception as exc:
            raise PyBurpClientError(
                f"gRPC raw request call failed: {exc}"
            ) from exc

    @staticmethod
    def _serialize_request(data: dict) -> bytes:
        """Serialize request data to bytes for gRPC transport."""
        import json
        return json.dumps(data).encode("utf-8")

    @staticmethod
    def _deserialize_response(data: bytes) -> dict:
        """Deserialize gRPC response bytes to a dict."""
        import json
        return json.loads(data.decode("utf-8"))

    def health_check(self) -> bool:
        """Check if the PyBurp gRPC server is reachable."""
        try:
            self._ensure_connected()
            import grpc

            # Use gRPC health check or a simple reflection call
            channel_method = self._channel.unary_unary(
                "/pyburp.PyBurpService/HealthCheck",
                request_serializer=self._serialize_request,
                response_deserializer=self._deserialize_response,
            )
            response = channel_method({}, timeout=5)
            return response.get("status") == "ok"
        except Exception:
            return False
