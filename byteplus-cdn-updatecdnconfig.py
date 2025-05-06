import hashlib
import hmac
import datetime
import json
from urllib.parse import quote
import requests

# The following parameters vary based on the service and are usually consistent within a service.
Service = "cdn"
Version = "2021-03-01"
Region = "ap-singapore-1"
Host = "cdn.byteplusapi.com"
ContentType = "application/json; charset=utf-8"

# Request credential, obtained from Identity and Access Management (IAM) or Security Token Service (STS)
AK = ""
SK = ""

def norm_query(params):
    query = ""
    for key in sorted(params.keys()):
        if type(params[key]) == list:
            for k in params[key]:
                query = (
                        query + quote(key, safe="-_.~") + "=" + quote(k, safe="-_.~") + "&"
                )
        else:
            query = (query + quote(key, safe="-_.~") + "=" + quote(params[key], safe="-_.~") + "&")
    query = query[:-1]
    return query.replace("+", "%20")


# Step 1: Prepare an auxiliary function.
# SHA-256 asymmetric encryption
def hmac_sha256(key: bytes, content: str):
    return hmac.new(key, content.encode("utf-8"), hashlib.sha256).digest()


# SHA-256 hash algorithm
def hash_sha256(content: str):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# Step 2: Sign the request function.
def request(method, date, query, header, ak, sk, action, body):
    # Step 3: Create an identity credential.
    credential = {
        "access_key_id": ak,
        "secret_access_key": sk,
        "service": Service,
        "region": Region,
    }
    # Initialize the signature struct.
    request_param = {
        "body": body,
        "host": Host,
        "path": "/",
        "method": method,
        "content_type": ContentType,
        "date": date,
        "query": {"Action": action, "Version": Version, **query},
    }
    if body is None:
        request_param["body"] = ""

    # Step 4: Prepare a signResult variable for receiving the signature calculation result
    x_date = request_param["date"].strftime("%Y%m%dT%H%M%SZ")
    short_x_date = x_date[:8]
    x_content_sha256 = hash_sha256(request_param["body"])
    sign_result = {
        "Host": request_param["host"],
        "X-Content-Sha256": x_content_sha256,
        "X-Date": x_date,
        "Content-Type": request_param["content_type"],
    }

    # Step 5: Calculate a signature.
    signed_headers_str = ";".join(
        ["content-type", "host", "x-content-sha256", "x-date"]
    )
    canonical_request_str = "\n".join(
        [request_param["method"].upper(),
         request_param["path"],
         norm_query(request_param["query"]),
         "\n".join(
             [
                 "content-type:" + request_param["content_type"],
                 "host:" + request_param["host"],
                 "x-content-sha256:" + x_content_sha256,
                 "x-date:" + x_date,
             ]
         ),
         "",
         signed_headers_str,
         x_content_sha256,
         ]
    )

    # Print the normalized request for debugging and comparison.
    print("Canonical Request:")
    print(canonical_request_str)
    hashed_canonical_request = hash_sha256(canonical_request_str)

    # Print the hash value for debugging and comparison.
    print("Hashed Canonical Request:")
    print(hashed_canonical_request)
    credential_scope = "/".join([short_x_date, credential["region"], credential["service"], "request"])
    string_to_sign = "\n".join(["HMAC-SHA256", x_date, credential_scope, hashed_canonical_request])

    # Print the eventually calculated signature string for debugging and comparison.
    print("String to Sign:")
    print(string_to_sign)
    k_date = hmac_sha256(credential["secret_access_key"].encode("utf-8"), short_x_date)
    k_region = hmac_sha256(k_date, credential["region"])
    k_service = hmac_sha256(k_region, credential["service"])
    k_signing = hmac_sha256(k_service, "request")
    signature = hmac_sha256(k_signing, string_to_sign).hex()

    sign_result["Authorization"] = "HMAC-SHA256 Credential={}, SignedHeaders={}, Signature={}".format(
        credential["access_key_id"] + "/" + credential_scope,
        signed_headers_str,
        signature,
    )
    header = {**header, **sign_result}

    # Step 6: Send the HTTP request
    r = requests.request(method=method,
                         url="https://{}{}".format(request_param["host"], request_param["path"]),
                         headers=header,
                         params=request_param["query"],
                         data=request_param["body"],
                         )
    return r.json()


if __name__ == "__main__":
    now = datetime.datetime.utcnow()

    # Construct the query parameters for UpdateCdnConfig API
    query_params = {}

    body_dict = {
        "Domain": "www.hannana.com.cn",  # 替换成你的域名
        "HTTPS": {
            "Switch": True,
            "CertInfo": {
                "CertId": "cert-55f4995952d44696a3c11efba24a13b0"  # 替换成你的 CertId
            },
            "DisableHttp": False,
            "ForcedRedirect": {
                "EnableForcedRedirect": True,
                "StatusCode": "301"
            },
            "HTTP2": True,
            "Ocsp": True,
            "TlsVersion": ["tlsv1.1", "tlsv1.2"]
        }
    }

    body_json = json.dumps(body_dict)
    # Call the API
    response = request("POST", now, query_params, {}, AK, SK, "UpdateCdnConfig", body_json)

    # Print the response
    print(json.dumps(response, indent=2))
