import re
from typing import Any, Mapping, NamedTuple
from unittest.mock import patch

import pytest
from urllib3 import HTTPResponse

from urllib3_sigv4 import PoolManager, SigV4RequestSigner, request


class InvalidAuthorizationHeader(Exception):
    """Invalid SigV4 authorization header."""


class AuthorizationHeader(NamedTuple):
    """Components of the SigV4 authorization header."""

    algorithm: str
    access_key: str
    date: str
    region: str
    service: str
    signed_headers: list[str]
    signature: str


def parse_authorization_header(value: str) -> AuthorizationHeader:
    """Parse the authorization header of a signed request.

    See:
    https://docs.aws.amazon.com/IAM/latest/UserGuide/signing-elements.html
    https://docs.aws.amazon.com/IAM/latest/UserGuide/aws-signing-authentication-methods.html
    """
    pattern = r"""
        (?P<algorithm>AWS4-HMAC-SHA256)\s
        Credential=(?P<access_key>.+)/(?P<date>.+)/(?P<region>.+)/(?P<service>.+)/aws4_request,\s
        SignedHeaders=(?P<signed_headers>.+),\s
        Signature=(?P<signature>.+)
    """
    match = re.fullmatch(pattern, value, re.VERBOSE)
    if match is None:
        raise InvalidAuthorizationHeader("Invalid SigV4 authorization header")
    components = match.groupdict()
    components["signed_headers"] = components["signed_headers"].split(";")
    return AuthorizationHeader(**components)  # type: ignore


def keys_to_lower(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    """Convert object keys to lowercase."""
    return {k.lower(): v for k, v in obj.items()}


@pytest.fixture
def signer() -> SigV4RequestSigner:
    return SigV4RequestSigner(
        "lambda",
        region="eu-central-1",
        access_key="AKIA5UOOJB91ZKS7WUTM",
        secret_key="jFqVTJ/gBWYwD9pWZmwDg2w91nJFReQCw4se1DWc",
    )


@pytest.fixture
def another_signer() -> SigV4RequestSigner:
    return SigV4RequestSigner(
        "lambda",
        region="eu-central-1",
        access_key="AKIA6GUPFGQIB5OUKIYM",
        secret_key="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",
    )


@pytest.fixture
def pool() -> PoolManager:
    return PoolManager()


@pytest.fixture
def pool_with_signer(signer: SigV4RequestSigner) -> PoolManager:
    return PoolManager(signer=signer)


class TestPoolManager:
    def test_not_signed(self, pool: PoolManager) -> None:
        """Check requests are not signed by default."""
        with patch(
            "urllib3.connectionpool.HTTPConnectionPool.urlopen",
            return_value=HTTPResponse(),
        ) as urlopen:
            pool.request(
                "GET",
                "https://my-lambda-url-id.lambda-url.eu-central-1.on.aws",
            )
        urlopen.assert_called_once()
        headers = keys_to_lower(urlopen.call_args.kwargs["headers"])
        assert "authorization" not in headers

    def test_pool_signer(self, pool_with_signer: PoolManager) -> None:
        """Check requests are signed by default if pool created with signer."""
        with patch(
            "urllib3.connectionpool.HTTPConnectionPool.urlopen",
            return_value=HTTPResponse(),
        ) as urlopen:
            pool_with_signer.request(
                "GET",
                "https://my-lambda-url-id.lambda-url.eu-central-1.on.aws",
            )
        urlopen.assert_called_once()
        headers = keys_to_lower(urlopen.call_args.kwargs["headers"])
        assert "authorization" in headers
        parse_authorization_header(headers["authorization"])

    def test_request_signer(
        self, pool: PoolManager, signer: SigV4RequestSigner
    ) -> None:
        """Check individual request is signed with provided signer."""
        with patch(
            "urllib3.connectionpool.HTTPConnectionPool.urlopen",
            return_value=HTTPResponse(),
        ) as urlopen:
            pool.request(
                "GET",
                "https://my-lambda-url-id.lambda-url.eu-central-1.on.aws",
                signer=signer,
            )
        urlopen.assert_called_once()
        headers = keys_to_lower(urlopen.call_args.kwargs["headers"])
        assert "authorization" in headers
        parse_authorization_header(headers["authorization"])

    def test_signer_precedence(
        self, pool_with_signer: PoolManager, another_signer: SigV4RequestSigner
    ) -> None:
        """Check request signer takes precedence over pool signer."""
        with patch(
            "urllib3.connectionpool.HTTPConnectionPool.urlopen",
            return_value=HTTPResponse(),
        ) as urlopen:
            pool_with_signer.request(
                "GET",
                "https://my-lambda-url-id.lambda-url.eu-central-1.on.aws",
                signer=another_signer,
            )
        urlopen.assert_called_once()
        headers = keys_to_lower(urlopen.call_args.kwargs["headers"])
        assert "authorization" in headers
        authorization = parse_authorization_header(headers["authorization"])
        assert (
            authorization.access_key == another_signer.credentials.access_key
        )


class TestRequest:
    def test_not_signed(self) -> None:
        """Check request is not signed by default."""
        with patch(
            "urllib3.connectionpool.HTTPConnectionPool.urlopen",
            return_value=HTTPResponse(),
        ) as urlopen:
            request(
                "GET",
                "https://my-lambda-url-id.lambda-url.eu-central-1.on.aws",
            )
        urlopen.assert_called_once()
        headers = keys_to_lower(urlopen.call_args.kwargs["headers"])
        assert "authorization" not in headers

    def test_signer(self, signer: SigV4RequestSigner) -> None:
        """Check request is signed with provided signer."""
        with patch(
            "urllib3.connectionpool.HTTPConnectionPool.urlopen",
            return_value=HTTPResponse(),
        ) as urlopen:
            request(
                "GET",
                "https://my-lambda-url-id.lambda-url.eu-central-1.on.aws",
                signer=signer,
            )
        urlopen.assert_called_once()
        headers = keys_to_lower(urlopen.call_args.kwargs["headers"])
        assert "authorization" in headers
        parse_authorization_header(headers["authorization"])
