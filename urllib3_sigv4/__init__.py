from contextvars import ContextVar
from typing import Any, Mapping

import boto3
import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import NoCredentialsError, NoRegionError
from urllib3._base_connection import _TYPE_BODY
from urllib3.filepost import _TYPE_FIELDS
from urllib3.response import BaseHTTPResponse


class SigV4RequestSigner(SigV4Auth):
    """Sign a request with AWS Signature Version 4.

    If the region or credentials are omitted, try to use values from the
    default Boto3 session.
    """

    def __init__(
        self,
        service: str,
        region: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
    ):
        session = boto3._get_default_session()
        region = session.region_name if region is None else region
        if region is None:
            raise NoRegionError()
        if access_key is None or secret_key is None:
            credentials = session.get_credentials()
            if credentials is None:
                raise NoCredentialsError()
        else:
            credentials = Credentials(access_key, secret_key)
        super().__init__(credentials.get_frozen_credentials(), service, region)


class PoolManager(urllib3.PoolManager):
    """Pool manager enhanced with support for signing requests with AWS SigV4.

    It allows specifying a request signer either on instance or individual
    request level. If both are provided, the request level signer takes
    precedence.
    """

    def __init__(
        self,
        num_pools: int = 10,
        headers: Mapping[str, str] | None = None,
        signer: SigV4RequestSigner | None = None,
        **connection_pool_kw: Any,
    ) -> None:
        super().__init__(
            num_pools=num_pools, headers=headers, **connection_pool_kw
        )
        self.signer = signer

    def request(
        self,
        method: str,
        url: str,
        body: _TYPE_BODY | None = None,
        fields: _TYPE_FIELDS | None = None,
        headers: Mapping[str, str] | None = None,
        json: Any | None = None,
        signer: SigV4RequestSigner | None = None,
        **urlopen_kw: Any,
    ) -> BaseHTTPResponse:
        # Propagate the signer downstream via a context variable so we can sign
        # the request as late as possible after any potential transformations
        # performed before making the request.
        _signer.set(signer or self.signer)

        return super().request(
            method,
            url,
            body=body,
            fields=fields,
            headers=headers,
            json=json,
            **urlopen_kw,
        )

    def urlopen(
        self, method: str, url: str, redirect: bool = True, **kw: Any
    ) -> BaseHTTPResponse:
        # Sign the request if required before making the actual HTTP request.
        signer = _signer.get()
        if signer is not None:
            headers = kw.get("headers")
            body = kw.get("body")
            request = AWSRequest(
                method=method, url=url, headers=headers, data=body
            )
            signer.add_auth(request)
            prepared_request = request.prepare()
            url = prepared_request.url
            kw["headers"] = dict(prepared_request.headers)
            if prepared_request.body:
                kw["body"] = prepared_request.body

        return super().urlopen(method, url, redirect=redirect, **kw)


def request(
    method: str,
    url: str,
    *,
    body: _TYPE_BODY | None = None,
    fields: _TYPE_FIELDS | None = None,
    headers: Mapping[str, str] | None = None,
    preload_content: bool | None = True,
    decode_content: bool | None = True,
    redirect: bool | None = True,
    retries: urllib3.Retry | bool | int | None = None,
    timeout: urllib3.Timeout | float | int | None = 3,
    json: Any | None = None,
    signer: SigV4RequestSigner | None = None,
) -> BaseHTTPResponse:
    """Top-level request method adding support for signing with AWS SigV4."""
    return _DEFAULT_POOL.request(
        method,
        url,
        body=body,
        fields=fields,
        headers=headers,
        preload_content=preload_content,
        decode_content=decode_content,
        redirect=redirect,
        retries=retries,
        timeout=timeout,
        json=json,
        signer=signer,
    )


_signer: ContextVar[SigV4RequestSigner | None] = ContextVar(
    "signer", default=None
)
_DEFAULT_POOL = PoolManager()
