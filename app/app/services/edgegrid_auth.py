"""
Akamai EdgeGrid HMAC authentication for httpx.
Ports the signing algorithm from edgegrid-python to an httpx.Auth subclass.
"""
import base64
import hashlib
import hmac
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

import httpx


class EdgeGridAuth(httpx.Auth):
    """httpx Auth subclass that signs requests with Akamai EdgeGrid HMAC-SHA256."""

    MAX_BODY = 131072  # 128 KB — matches edgegrid-python default

    def __init__(self, client_token: str, client_secret: str, access_token: str):
        self.client_token = client_token
        self.client_secret = client_secret
        self.access_token = access_token

    # Works for both sync and async httpx clients.
    def auth_flow(self, request: httpx.Request) -> Generator:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H:%M:%S+0000")
        nonce = str(uuid.uuid4())
        request.headers["Authorization"] = self._build_auth_header(
            request, timestamp, nonce
        )
        yield request

    # ------------------------------------------------------------------ helpers

    def _build_auth_header(
        self, request: httpx.Request, timestamp: str, nonce: str
    ) -> str:
        auth_data = (
            f"EG1-HMAC-SHA256 "
            f"client_token={self.client_token};"
            f"access_token={self.access_token};"
            f"timestamp={timestamp};"
            f"nonce={nonce};"
        )
        signature = self._sign(request, timestamp, auth_data)
        return auth_data + f"signature={signature}"

    def _sign(
        self, request: httpx.Request, timestamp: str, auth_data: str
    ) -> str:
        url = request.url
        path_and_query = url.raw_path.decode("utf-8")

        # Content hash: SHA-256 of first MAX_BODY bytes of POST body.
        content_hash = ""
        if request.method.upper() == "POST" and request.content:
            body = request.content[: self.MAX_BODY]
            content_hash = base64.b64encode(
                hashlib.sha256(body).digest()
            ).decode("ascii")

        data_to_sign = "\t".join(
            [
                request.method.upper(),
                url.scheme,
                url.host,
                path_and_query,
                "",  # canonical headers — not used
                content_hash,
                auth_data,
            ]
        )

        # Intermediate key: HMAC-SHA256(client_secret, timestamp), base64-encoded.
        signing_key = base64.b64encode(
            hmac.new(
                self.client_secret.encode("utf-8"),
                timestamp.encode("utf-8"),
                hashlib.sha256,
            ).digest()
        )

        # Final signature: HMAC-SHA256(signing_key, data_to_sign).
        signature = base64.b64encode(
            hmac.new(
                signing_key,
                data_to_sign.encode("utf-8"),
                hashlib.sha256,
            ).digest()
        ).decode("ascii")

        return signature


def auth_from_edgerc(edgerc_path: str, section: str = "default") -> tuple[str, EdgeGridAuth]:
    """
    Parse an Akamai .edgerc file and return (base_url, EdgeGridAuth).
    Uses the same edgerc format as edgegrid-python.
    """
    from akamai.edgegrid import EdgeRc

    edgerc = EdgeRc(str(Path(edgerc_path).expanduser()))
    base_url = f"https://{edgerc.get(section, 'host')}"
    auth = EdgeGridAuth(
        client_token=edgerc.get(section, "client_token"),
        client_secret=edgerc.get(section, "client_secret"),
        access_token=edgerc.get(section, "access_token"),
    )
    return base_url, auth
