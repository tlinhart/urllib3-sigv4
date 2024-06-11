# urllib3 SigV4

Extension to [urllib3](https://github.com/urllib3/urllib3) adding support for
signing the requests with AWS Signature Version 4. It uses the
[Boto3](https://github.com/boto/boto3) library for handling the AWS credentials
and the actual signing process.

## Installation

Use `pip` to install the package:

```bash
pip install urllib3_sigv4
```

## Usage

This library provides a drop-in replacement for two main components of urllib3,
the [`PoolManager`](https://urllib3.readthedocs.io/en/stable/reference/urllib3.poolmanager.html)
class and the top-level [`request`](https://urllib3.readthedocs.io/en/stable/reference/urllib3.request.html)
method. It adds a new optional parameter which determines if and how the
requests should be signed.

### Creating a Signer

First, create an instance of the `SigV4RequestSigner` class which defines the
parameters for request signing:

```python
from urllib3_sigv4 import SigV4RequestSigner

signer = SigV4RequestSigner(
    "lambda",
    region="eu-central-1",
    access_key="AKIAIOSFODNN7EXAMPLE",
    secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)
```

The first parameter is mandatory and identifies the AWS service we want to make
requests to (AWS Lambda in this case). The `region`, `access_key` and
`secret_key` parameters are optional and will be inferred from the environment
if not passed (via the default Boto3 session, see
[here](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/session.html)
and [here](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html)
for more details).

### Making Requests

To make signed requests to an AWS service, pass the signer instance via the
`signer` parameter when creating the `PoolManager`:

```python
from urllib3_sigv4 import PoolManager, SigV4RequestSigner

signer = SigV4RequestSigner("lambda")
http = PoolManager(signer=signer)

response = http.request(
    "POST",
    "https://my-lambda-url-id.lambda-url.eu-central-1.on.aws",
    json={"name": "John Doe", "age": 30}
)
print(response.json())
```

You can also provide the signer in individual `request` method calls to
override the default behavior:

```python
from urllib3_sigv4 import PoolManager, SigV4RequestSigner

signer = SigV4RequestSigner("lambda")
http = PoolManager()

# The same as when using urllib3's PoolManager.
response = http.request("GET", "https://httpbin.org/get")
print(response.json())

# This request will be signed.
response = http.request(
    "POST",
    "https://my-lambda-url-id.lambda-url.eu-central-1.on.aws",
    json={"name": "John Doe", "age": 30},
    signer=signer
)
print(response.json())
```

You can also use a convenience top-level `request` method which uses a
module-global `PoolManager` instance:

```python
from urllib3_sigv4 import SigV4RequestSigner, request

signer = SigV4RequestSigner("lambda")

response = request(
    "POST",
    "https://my-lambda-url-id.lambda-url.eu-central-1.on.aws",
    json={"name": "John Doe", "age": 30},
    signer=signer
)
print(response.json())
```

## Reference

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html
- https://github.com/aws-samples/sigv4-signing-examples
- https://github.com/awslabs/aws-sdk-python-signers
