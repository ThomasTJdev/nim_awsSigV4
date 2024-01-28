# awsSigV4

This package implements the AWS Signature Version 4 signing process. It provides
the core procedures for generating the canonical request, signed
headers, and for computing the signature itself. The presigned URL's can be
used to call AWS services directly - e.g. accessing S3 objects, invoking Lambda
functions, etc.

With the three main procedures, it's possible to implement the signing process:
1. `canonicalRequest()` - generates the canonical request
2. `stringToSign()` - generates the string to sign
3. `calculateSignature()` - generates the signature

Besides the three main procedures, there are also two helper procedures:
1. `makeDateTime()` - generates the date and time in the format required by AWS
2. `credentialScope()` - generates the credential scope


## Example

Please see the `tests/` for a full replicatable example.

```nim
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
  datetime  = makeDateTime()

let
  scope     = credentialScope(region=region, service=service, date=datetime)
  headers   = newHttpHeaders(@[("Host", bucketHost)])

var
  query = %*{
            "X-Amz-Algorithm": $SHA256,
            "X-Amz-Credential": accessKey & "/" & scope,
            "X-Amz-Date": datetime,
            "X-Amz-Expires": expireSec,
          }

# Using STS? Remember the token:
if tokenKey != "":
  query["X-Amz-Security-Token"] = newJString(tokenKey)

query["X-Amz-SignedHeaders"] = newJString("host")


let
  request = canonicalRequest(httpMethod, url, query, headers, payload,
                            digest = UnsignedPayload)

  sts = stringToSign(request, scope, date = datetime, digest = SHA256)

  signature = calculateSignature(secret=secretKey, date = datetime, region = region,
                                service = service, tosign = sts, digest = SHA256)

let
  presigned = url & "?" & request.split("\n")[2] & "&X-Amz-Signature=" & signature
```


## Original Sources

This project is a rewrite of original code from the following sources:
- [sigv4](https://github.com/disruptek/sigv4)
- [depot](https://github.com/guzba/depot)

The motivation for this rewrite was to eliminate the dependency on the `balls` package that was present in the `sigv4` package.

Now, this code only has a dependency on the `crunchy` package by @guzba.


## Use Cases

This package is used by the following packages:
- [awsS3](https://github.com/ThomasTJdev/nim_awsS3)
- [awsSTS](https://github.com/ThomasTJdev/nim_awsSTS)


## Debugging

If your signature is not working, run the same command with `aws cli` using
the `--debug` flag. This will print out the signature that `aws cli` is
generating. Compare this to the signature that this package is generating.

