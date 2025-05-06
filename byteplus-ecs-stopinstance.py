import datetime
import hashlib
import hmac
from urllib.parse import quote
import requests

# 以下参数根据服务不同有所变化，这里针对 ECS 服务
Service = "ecs"  # 更改为 ECS 服务
Version = "2020-04-01"  # StopInstance 的 API 版本
Region = "ap-southeast-1"  # ECS 所在区域
Host = "open.ap-southeast-1.byteplusapi.com"  # ECS 的 API Host
ContentType = "application/x-www-form-urlencoded"  # 请求体类型

# 请求凭证，从 IAM 或 STS 获取
AK = ""
SK = ""


def norm_query(params):
    query = ""
    for key in sorted(params.keys()):
        if isinstance(params[key], list):
            for k in params[key]:
                query = (
                        query + quote(key, safe="-_.~") + "=" + quote(k, safe="-_.~") + "&"
                )
        else:
            query = (query + quote(key, safe="-_.~") + "=" + quote(params[key], safe="-_.~") + "&")
    query = query[:-1]
    return query.replace("+", "%20")


# HMAC-SHA256 加密函数
def hmac_sha256(key: bytes, content: str):
    return hmac.new(key, content.encode("utf-8"), hashlib.sha256).digest()


# SHA-256 哈希函数
def hash_sha256(content: str):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def request(method, date, query, header, ak, sk, action, body):
    credential = {
        "access_key_id": ak,
        "secret_access_key": sk,
        "service": Service,
        "region": Region,
    }

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

    x_date = request_param["date"].strftime("%Y%m%dT%H%M%SZ")
    short_x_date = x_date[:8]
    x_content_sha256 = hash_sha256(request_param["body"])

    sign_result = {
        "Host": request_param["host"],
        "X-Content-Sha256": x_content_sha256,
        "X-Date": x_date,
        "Content-Type": request_param["content_type"],
    }

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

    hashed_canonical_request = hash_sha256(canonical_request_str)

    credential_scope = "/".join([short_x_date, credential["region"], credential["service"], "request"])
    string_to_sign = "\n".join(["HMAC-SHA256", x_date, credential_scope, hashed_canonical_request])

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

    r = requests.request(method=method,
                         url="https://{}{}".format(request_param["host"], request_param["path"]),
                         headers=header,
                         params=request_param["query"],
                         data=request_param["body"],
                         )
    return r.json()


if __name__ == "__main__":
    now = datetime.datetime.utcnow()
    instance_id = "i-ydh47gdzb48lu7j064ty"  # 替换为你的实例 ID
    # 可选参数
    query_params = {
        "InstanceId": instance_id,
        "StoppedMode": "StopCharging",  # 可选，设置为需要的停止模式
        "ForceStop": "false",  # 可选，是否强制停止
        "DryRun": "false",  # 可选，是否进行预检查
    }

    response_body = request("GET", now, query_params, {}, AK, SK, "StopInstance", None)
    print(response_body)
