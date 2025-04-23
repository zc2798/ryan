import datetime
import hashlib
import hmac
from urllib.parse import quote
import requests

# The following parameters vary based on the service and are usually consistent within a service.
Service = "vod"
Version = "2023-01-01"
Region = "ap-singapore-1"
Host = "vod.byteplusapi.com"
ContentType = "application/x-www-form-urlencoded"

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
    # The values of the Service and Region fields are fixed and the values of the ak and sk fields indicate an access key ID and a secret access key, respectively.
    # Signature struct initialization is also required. Some attributes required for signature calculation also need to be processed here.
    # Initialize the identity credential struct.
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
        "query": {"Action": action, "Version": Version, "SpaceName": "test1adasd", **query},
    }
    if body is None:
        request_param["body"] = ""

    # Step 4: Prepare a signResult variable for receiving the signature calculation result and set the required parameters.
    # Initialize the signature result struct.
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
    print(canonical_request_str)
    hashed_canonical_request = hash_sha256(canonical_request_str)

    # Print the hash value for debugging and comparison.
    print(hashed_canonical_request)
    credential_scope = "/".join([short_x_date, credential["region"], credential["service"], "request"])
    string_to_sign = "\n".join(["HMAC-SHA256", x_date, credential_scope, hashed_canonical_request])

    # Print the eventually calculated signature string for debugging and comparison.
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
    # header = {**header, **{"X-Security-Token": SessionToken}}

    # Step 6: Write the signature into the HTTP header and send the HTTP request.
    r = requests.request(method=method,
                         url="https://{}{}".format(request_param["host"], request_param["path"]),
                         headers=header,
                         params=request_param["query"],
                         data=request_param["body"],
                         )
    return r.json()


if __name__ == "__main__":
    now = datetime.datetime.utcnow()

    # Construct the query parameters for CreatePlaylist API
    query_params = {
        "Name": "zctest",  # Name of the playlist
        "Vids": "v1120cg50000d04g3rvak5v7hns4kcn0,v1120cg50000d04g3tnak5v6ovscsj40,v1120cg50000d04g3snak5v6ovscsj20,v1120cg50000d04g3tfak5v064ojdlng,v1120cg50000d04g3snak5v064ojdljg,v1120cg50000d04g3rvak5v3lc4fbn1g,v1120cg50000d04g3tnak5v8rjj2hv10,v1120cg50000d04g3svak5v3lc4fbn60,v1120cg50000d04g3tnak5v8rjj2hv0g,v1120cg50000d04g3svak5v064ojdllg,v1120cg50000d04g3snak5v8rjj2hutg,v1120cg50000d04g3rvak5v7hns4kcng,v1120cg50000d04g3rnak5v3lc4fbn10,v1120cg50000d04g3svak5v3lc4fbn6g,v1120cg50000d04g3tfak5v064ojdlo0,v1120cg50000d04g3snak5v064ojdlk0,v1120cg50000d04g3svak5v7hns4kcs0,v1120cg50000d04g3t7ak5v6ovscsj30,v1120cg50000d04g3t7ak5v3lc4fbn7g,v1120cg50000d04g3svak5v8rjj2huu0,v1120cg50000d04g3snak5v064ojdlkg,v1120cg50000d04g3svak5v8rjj2huug,v1120cg50000d04g3svak5v6ovscsj2g,v1120cg50000d04g3t7ak5v3lc4fbn70,v1120cg50000d04g3sfak5v3lc4fbn2g,v1120cg50000d04g3s7ak5v064ojdlhg,v1120cg50000d04g3sfak5v3lc4fbn40,v1120cg50000d04g3s7ak5v7hns4kcog,v1120cg50000d04g3rvak5v7hns4kcmg,v1120cg50000d04g3snak5v3lc4fbn5g,v1120cg50000d04g3snak5v3lc4fbn50,v1120cg50000d04g3t7ak5v8rjj2hv00,v1120cg50000d04g3tfak5v064ojdlog,v1120cg50000d04g3sfak5v8rjj2husg,v1120cg50000d04g3t7ak5v064ojdlm0,v1120cg50000d04g3sfak5v3lc4fbn3g,v1120cg50000d04g3tfak5v064ojdln0,v1120cg50000d04g3t7ak5v6ovscsj3g,v1120cg50000d04g3s7ak5v7hns4kcp0,v1120cg50000d04g3svak5v8rjj2huv0,v1120cg50000d04g3t7ak5v064ojdlmg,v1120cg50000d04g3t7ak5v8rjj2huvg,v1120cg50000d04g3svak5v064ojdll0,v1120cg50000d04g3svak5v7hns4kcrg,v1120cg50000d04g3snak5v7hns4kcr0,v1120cg50000d04g3snak5v7hns4kcqg,v1120cg50000d04g3sfak5v3lc4fbn4g,v1120cg50000d04g3sfak5v6ovscsj10,v1120cg50000d04g3sfak5v064ojdli0,v1120cg50000d04g3rfak5v064ojdlgg,v1120cg50000d04g3sfak5v3lc4fbn30,v1120cg50000d04g3sfak5v8rjj2hut0,v1120cg50000d04g3sfak5v7hns4kcq0,v1120cg50000d04g3s7ak5v7hns4kcpg,v1120cg50000d04g3sfak5v064ojdlig,v1120cg50000d04g3sfak5v064ojdlj0,v1120cg50000d04g3s7ak5v6ovscsj0g,v1120cg50000d04g3s7ak5v8rjj2hus0,v1120cg50000d04g3rnak5v7hns4kcm0,v1120cg50000d04g3rvak5v3lc4fbn20",  # IDs of the videos in the playlist
        "Format": "mp4",  # Container format (e.g., mp4, dash, hls)
        "Codec": "H264",  # Codec (e.g., H264, AAC)
        "Definition": "1080p",  # Resolution (e.g., 720p, 1080p, 4k)
        "StartTime": "0",  # Start time (optional)
        "EndTime": "3600",  # End time (optional)
        "Cycles": "1",  # Number of cycles (0 for infinite)
    }

    # Call the API
    response_body = request("GET", now, query_params, {}, AK, SK, "CreatePlaylist", None)

    # Print the response
    print(response_body)
