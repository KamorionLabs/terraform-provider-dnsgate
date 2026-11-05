# terraform-provider-dnsgate

Terraform / OpenTofu provider for [dns-gate](https://github.com/KamorionLabs/dns-gate), a security gateway
in front of DNS provider APIs (EuroDNS, Route53...).

The gate holds the DNS provider credentials. Terraform only presents a short-lived identity (AWS STS web
identity, Entra ID, Azure DevOps or GitHub Actions OIDC...), and the gate enforces RBAC per zone, name and
type, **per-RRset ownership by team**, conditional writes and a full audit trail. The provider is
provider-neutral: one `dnsgate_record_set` resource for a EuroDNS zone or a Route53 hosted zone, alias
records included.

> Status: **beta**, versions 0.x. Needs a gate that advertises the `rrset-api` feature
> (`GET /.well-known/dns-gate`). For EuroDNS-only setups,
> [terraform-provider-eurodns](https://github.com/KamorionLabs/terraform-provider-eurodns) also works through
> the gate (EuroDNS-compatible API).

```hcl
terraform {
  required_providers {
    dnsgate = { source = "KamorionLabs/dnsgate" }
  }
}

provider "dnsgate" {
  endpoint = "https://dns-gate.example.com"
  auth {
    aws_web_identity { audience = "dns-gate" }
  }
}

resource "dnsgate_record_set" "www" {
  zone   = "example.com"
  name   = "www"
  type   = "CNAME"
  ttl    = 300
  values = ["front.example.net"]
}

resource "dnsgate_record_set" "apex" {
  zone = "example.com"
  name = "@"
  type = "A"
  alias {
    name                   = "d111111abcdef8.cloudfront.net"
    zone_id                = "Z2FDTNDATAQYW2"
    evaluate_target_health = false
  }
}
```

## Resources and data sources

| Name | |
|---|---|
| `dnsgate_record_set` | One RRset (all records of a name and type), values or alias. Id and import id `<zone>/<name>/<type>`. |
| `dnsgate_role`, `dnsgate_binding` | Roles and bindings of the gate's managed policy, owned by a policy delegation (for stacks that create pipelines). |
| `dnsgate_zones` (data) | Zones readable by the identity, with ownership counts. |
| `dnsgate_record_sets` (data) | Zone inventory with ownership, filtered by name glob, type, owner team, status. |
| `dnsgate_record_set` (data) | One RRset, whoever owns it. |

Documentation: [docs/](docs/index.md), generated from `templates/` and `examples/` (`make docs`).

## How a record set is written

The provider uses the gate REST API, one RRset per request:

| Operation | Request |
|---|---|
| Create | `PUT /api/v1/zones/{zone}/rrsets/{name}/{type}` with `If-None-Match: *` |
| Read | `GET` the same path (404: removed from the state) |
| Update | `PUT` with `If-Match: "<hash>"`, the content hash kept in the private state at the last refresh or write |
| Delete | `DELETE` with `If-Match: "<hash>"` |
| Import | `GET`, refused unless the RRset is owned by the team of the identity |

A change made in the gate since the last refresh fails with `412` instead of being overwritten. `423
zone_locked`, `429`, `5xx` (`store_unavailable` included) and transport errors are retried with exponential
backoff and `Retry-After`; if a write is refused after a retry because an earlier attempt went through, the
provider reads the RRset back and accepts it when it holds the desired content.

## Value comparison

The gate (or Route53 behind it) may store a value in another form than the configuration. Values are
compared by meaning with the zone file parser of [miekg/dns](https://github.com/miekg/dns), the library the
gate's Route53 adapter uses to canonicalize them: names inside values are absolute and case-insensitive
(trailing dot optional), TXT/SPF values compare on their concatenated text (quoting and 255-byte chunking
ignored, an unquoted value is one string as with the AWS provider, so `a""b` is `"a" "b"`), other fields as
parsed (IPv6, CAA quoting). A value that does not parse compares as an exact string and draws a plan-time
warning. Alias names compare case-insensitively, trailing dot optional. When configuration and gate hold the
same records, the plan keeps the stored form: no diff after apply, after refresh or right after an import.
Details in the resource documentation.

## Migrating from aws_route53_record

The goal: move the ~hundreds of `aws_route53_record` of a stack under the gate, record by record, without any
DNS change, so that every later change is audited and owned by a team.

1. The gate administrators add the hosted zone to the gate (Route53 provider). Its RRsets show as `foreign`.
2. Adopt the RRsets for the team of the stack's pipeline in the gate (UI, or
   `POST /api/v1/zones/{zone}/adopt/preview` then `/adopt`).
3. Generate the configuration: `GET /api/v1/zones/{zone}/terraform?team=<team>` returns one
   `dnsgate_record_set` per RRset with its `import` block (alias records with an `alias` block, no `ttl`).
4. For each record, replace the `aws_route53_record` by the `dnsgate_record_set` and add:

   ```hcl
   removed {
     from = aws_route53_record.x
     lifecycle {
       destroy = false
     }
   }

   import {
     to = dnsgate_record_set.x
     id = "zone/name/TYPE" # e.g. "example.com/@/A"
   }
   ```

5. The first plan must show only imports and removals ("will no longer be managed by Terraform"), **no
   change**. Apply, then drop the `import` and `removed` blocks.

`removed` blocks need Terraform or OpenTofu >= 1.7. Names are relative to the zone (`www`, `@`), values can
keep the AWS provider's form. Records with `set_identifier` / routing policies are read-only in the gate. See
[the migration guide](docs/guides/migrating-from-route53.md) and
[examples/migration-route53](examples/migration-route53/main.tf).

## Authentication

Exactly one method in `auth`, plus optionally one CI method used only inside its CI system:
`aws_web_identity` (STS `GetWebIdentityToken` with audience), `azure_identity` (Entra ID: environment, AKS
workload identity, managed identity, Azure CLI), `azure_devops` (service connection OIDC token),
`github_actions` (job OIDC token), `token_file`, `token_command`, `token`. Without `auth`, `DNSGATE_TOKEN` or
`DNSGATE_TOKEN_FILE`. Endpoint: `endpoint` or `DNSGATE_ENDPOINT`. See
[the authentication guide](docs/guides/authentication.md).

## Development

```sh
make build lint
make test        # unit and resource tests against an in-memory fake gate, terraform from PATH
make test-tofu   # the same with OpenTofu
make testacc     # TF_ACC=1 against a real gate: DNSGATE_ENDPOINT, DNSGATE_TOKEN, DNSGATE_ACC_ZONE
make docs        # tfplugindocs
```

Layout:

| Path | |
|---|---|
| `internal/client` | Go client of the gate REST API: reason codes, retries, timeouts, ETags |
| `internal/auth` | Token sources (static, file, command, AWS STS, Entra ID, Azure DevOps, GitHub Actions) |
| `internal/rdata` | Value comparison (miekg/dns) |
| `internal/fakegate` | In-memory gate implementing the contract, used by the tests |
| `internal/provider` | Provider, resources, data sources |

## License

MIT, see [LICENSE](LICENSE).
