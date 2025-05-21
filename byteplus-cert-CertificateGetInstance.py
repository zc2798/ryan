import hashlib
import hmac
import datetime
import json
from urllib.parse import quote
import requests

Service = "certificate_service"
Version = "2021-06-01"
Region = "ap-singapore-1"
Host = "open.byteplusapi.com"
ContentType = "application/json; charset=utf-8"

AK = "AKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
SK = "TVdXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

def norm_query(params):
    query = ""
    for key in sorted(params.keys()):
        value = params[key]
        if isinstance(value, list):
            for v in value:
                query += quote(key, safe="-_.~") + "=" + quote(str(v), safe="-_.~") + "&"
        else:
            query += quote(key, safe="-_.~") + "=" + quote(str(value), safe="-_.~") + "&"
    return query.rstrip("&").replace("+", "%20")

def hmac_sha256(key: bytes, content: str):
    return hmac.new(key, content.encode("utf-8"), hashlib.sha256).digest()

def hash_sha256(content: str):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

def request(method, date, query, header, ak, sk, action):
    request_param = {
        "body": "",
        "host": Host,
        "path": "/",
        "method": method,
        "content_type": ContentType,
        "date": date,
        "query": {"Action": action, "Version": Version, **query},
    }

    x_date = date.strftime("%Y%m%dT%H%M%SZ")
    short_x_date = x_date[:8]
    x_content_sha256 = hash_sha256("")
    signed_headers_str = ";".join(["content-type", "host", "x-content-sha256", "x-date"])

    canonical_request_str = "\n".join([
        request_param["method"].upper(),
        request_param["path"],
        norm_query(request_param["query"]),
        "\n".join([
            f"content-type:{request_param['content_type']}",
            f"host:{request_param['host']}",
            f"x-content-sha256:{x_content_sha256}",
            f"x-date:{x_date}"
        ]),
        "",
        signed_headers_str,
        x_content_sha256
    ])

    hashed_canonical_request = hash_sha256(canonical_request_str)
    credential_scope = "/".join([short_x_date, Region, Service, "request"])
    string_to_sign = "\n".join(["HMAC-SHA256", x_date, credential_scope, hashed_canonical_request])

    k_date = hmac_sha256(sk.encode("utf-8"), short_x_date)
    k_region = hmac_sha256(k_date, Region)
    k_service = hmac_sha256(k_region, Service)
    k_signing = hmac_sha256(k_service, "request")
    signature = hmac_sha256(k_signing, string_to_sign).hex()

    authorization = (
        f"HMAC-SHA256 Credential={ak}/{credential_scope}, "
        f"SignedHeaders={signed_headers_str}, Signature={signature}"
    )

    headers = {
        "Content-Type": ContentType,
        "Host": Host,
        "X-Date": x_date,
        "X-Content-Sha256": x_content_sha256,
        "Authorization": authorization,
    }

    response = requests.request(
        method=method,
        url=f"https://{Host}/",
        headers=headers,
        params=request_param["query"]
    )

    return response.json()

if __name__ == "__main__":
    now = datetime.datetime.utcnow()
    query_params = {
        "instance_id": "cert-901eece36df54a62a32c5ccabb353955"
    }
    response = request("GET", now, query_params, {}, AK, SK, "CertificateGetInstance")
    print(json.dumps(response, indent=2, ensure_ascii=False))
