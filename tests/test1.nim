
import
  std/[
    httpclient,
    json,
    strutils
  ]

import unittest

import awsSigV4


let
  accessKey = "credsAccessKey"
  secretKey = "credsSecretKey"
  tokenKey  = "accessToken"

  bucketHost = "my-book-bucket.s3.amazonaws.com"
  key        = "files/test.txt"

  url       = "https://" & bucketHost & "/" & key
  region    = "us-east-1"
  service   = "s3"

  httpMethod = HttpGet

  payload   = ""
  digest    = SHA256
  expireSec = "65"
  datetime  = "20240127T063953Z" #makeDateTime()



test "check":

  let
    scope = credentialScope(region=region, service=service, date=datetime)

  var
    headers = newHttpHeaders(@[("Host", bucketHost)])

  var
    query = %*{
              "X-Amz-Algorithm": $SHA256,
              "X-Amz-Credential": accessKey & "/" & scope,
              "X-Amz-Date": datetime,
              "X-Amz-Expires": expireSec,
            }

  if tokenKey != "":
    query["X-Amz-Security-Token"] = newJString(tokenKey)

  query["X-Amz-SignedHeaders"] = newJString("host")

  let
    request = canonicalRequest(httpMethod, url, query, headers, payload, digest = UnsignedPayload)

    sts = stringToSign(request, scope, date = datetime, digest = digest)

    signature = calculateSignature(secret=secretKey, date = datetime, region = region,
                                  service = service, tosign = sts, digest = digest)

    presigned = url & "?" & request.split("\n")[2] & "&X-Amz-Signature=" & signature


  check scope == "20240127/us-east-1/s3/aws4_request"

  check request == """GET
/files/test.txt
X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=credsAccessKey%2F20240127%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240127T063953Z&X-Amz-Expires=65&X-Amz-Security-Token=accessToken&X-Amz-SignedHeaders=host
host:my-book-bucket.s3.amazonaws.com

host
UNSIGNED-PAYLOAD"""

  check sts == """AWS4-HMAC-SHA256
20240127T063953Z
20240127/us-east-1/s3/aws4_request
1c2b562407acf1217bbfc849e4b29452a5872b377948ff68883cc3542a45fc54"""

  check signature == "728536441af664fe91eabb8943699dc64c947d447a36d9e7b6220be5d27d3efd"

  check presigned == "https://my-book-bucket.s3.amazonaws.com/files/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=credsAccessKey%2F20240127%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240127T063953Z&X-Amz-Expires=65&X-Amz-Security-Token=accessToken&X-Amz-SignedHeaders=host&X-Amz-Signature=728536441af664fe91eabb8943699dc64c947d447a36d9e7b6220be5d27d3efd"


