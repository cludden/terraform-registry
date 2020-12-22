# terraform-registry
a private terraform registry that supports the following services:
- [x] [providers.v1](https://www.terraform.io/docs/internals/provider-registry-protocol.html)
  - backed by AWS DynamoDB & S3
- [ ] [modules.v1](https://www.terraform.io/docs/internals/module-registry-protocol.html)
- [ ] [login.v1](https://www.terraform.io/docs/commands/login.html)


## Installation
1. Download a [release](https://github.com/cludden/terraform-registry/releases)
2. Docker `docker run -it cludden/terraform-registry server -h`

## Server Configuration
| Field | Type | Description | Required |
| :--- | :---: | :--- | :---: |
| `oidc` | `object` | enable oidc authentication middleware | |
| `oidc.algorithms` | `list(string)` | list of supported algorithms | |
| `oidc.client_id` | `string` | oid cclient identifier | |
| `oidc.issuer` | `string` | oidc issuer url | `true` |
| `oidc.skip_expiry_check` | `bool` | disable expiration check | |
| `oidc.skip_issuer_check` | `bool` | disable issuer check | |
| `provider` | `object` | enable `providers.v1` service | |
| `provider.bucket` | `string` | name of s3 bucket where provider binaries and related files are stored | |
| `provider.credentials.id` | `string` | aws access key id | |
| `provider.credentials.profile` | `string` | aws profile | |
| `provider.credentials.role` | `string` | aws role to assume | |
| `provider.credentials.role_external_id` | `string` | aws role external id | |
| `provider.credentials.secret` | `string` | aws secret access key | |
| `provider.credentials.token` | `string` | aws session token | |
| `provider.endpoint` | `string` | override aws service endpoint | |
| `provider.prefix` | `string` | optional s3 bucket path prefix where provider binaries and related files are stored | |
| `provider.region` | `string` | aws region| |
| `provider.table` | `string` | name of dynamodb table where registry metadata is stored | |

## Getting Started
Run locally using *localstack*:
```shell
# start localstack
$ docker-compose up -d localstack

# set dummy credentials
$ export AWS_ACCESS_KEY_ID=foo AWS_SECRET_ACCESS_KEY=bar

# create dynamodb table
$ aws dynamodb create-table \
    --endpoint http://localhost:4566 \
    --table-name terraform-registry \
    --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
    --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST

# create s3 bucket
$ aws s3api create-bucket --endpoint http://localhost:4566 --bucket terraform-registry

# start registry server
$ docker-compose up registry
```

## Provider Registry V1
In addition to the standard endpoints defined by the  `providers.v1` protocol, this service exposes the following administrative endpoints:

### Register GPG Public Key
Create or update a gpg public key for distribution
```http
PUT /providers/v1/gpg-public-keys/{id}
```

| Parameter | Type | Description | Required |
| :--- | :---: | :--- | :---: |
| `ascii_armor` | `string` | an "ascii-armor" encoding of the public key associated with this GPG key | `true`  |
| `id` | `string` | uppercase-hexadecimal-formatted ID for this GPG key | `true` |

### Publish Version
Create or update a provider version. *Note: this endpoint simply marks a version as available, it should be called after the appropriate artifacts have been uploaded to s3.`
```http
PUT /providers/v1/{namespace}/{type}/{version}
```

| Parameter | Type | Description | Required |
| :--- | :---: | :--- | :---: |
| `gpg_public_key_id` | `string` | an "ascii-armor" encoding of the public key associated with this GPG key | `true` |
| `namespace` | `string` | Provider namespace | `true` |
| `platforms` | `list(object({arch = string, os = string}))` | List of available platforms | `true` |
| `protocols` | `list(string)` | List of supported protocols | `true` |
| `type` | `string` | Provider name | `true` |
| `version` | `string` | Provider version | `true` |

## License
Licensed under the [MIT License](LICENSE.md)  
Copyright (c) 2020 Chris Ludden
