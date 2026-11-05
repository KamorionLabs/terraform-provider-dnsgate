---
page_title: "Authenticating to dns-gate"
subcategory: ""
description: |-
  Choose how Terraform proves its identity to a dns-gate.
---

# Authenticating to dns-gate

Terraform never holds the DNS provider credentials: it sends a bearer token that the gate verifies (issuer,
audience, claims) and maps to roles and owner teams. `auth` takes exactly one method, plus optionally one CI
method (`azure_devops` or `github_actions`) that is used inside its CI system only, so the same configuration
runs in the pipeline and on a workstation.

| Method | Token | Typical use |
|--------|-------|-------------|
| `aws_web_identity` | JWT signed by AWS STS (`sts:GetWebIdentityToken`) for the current IAM principal | CI with an AWS role, EKS Pod Identity, CodeBuild |
| `azure_identity` | Microsoft Entra ID access token for the gate application | Azure DevOps (`AzureCLI@2`), AKS workload identity, managed identity, Azure CLI login |
| `azure_devops` | OIDC token Azure DevOps issues for a service connection | Azure DevOps jobs, without any cloud login |
| `github_actions` | OIDC token of the GitHub Actions job, with the gate's audience | GitHub Actions with `permissions: id-token: write` |
| `token_file` | File re-read on expiry | Projected Kubernetes service account tokens, GitLab `id_tokens` written to a file |
| `token_command` | stdout of a command, run again on expiry | Any other OIDC helper |
| `token` | Static value | Gate virtual keys, tests |

Without an `auth` block, `DNSGATE_TOKEN` (a token) or `DNSGATE_TOKEN_FILE` (a file) is used; the endpoint
comes from `endpoint` or `DNSGATE_ENDPOINT`. Tokens are cached and renewed two minutes before they expire.

## AWS

```terraform
# The provider talks to a dns-gate, which holds the DNS provider credentials
# (EuroDNS, Route53...) and enforces RBAC and per-RRset ownership. Terraform
# only proves its identity, here with a JWT signed by AWS STS for the current
# IAM role (IAM outbound identity federation).
terraform {
  required_providers {
    dnsgate = {
      source = "KamorionLabs/dnsgate"
    }
  }
}

provider "dnsgate" {
  endpoint = "https://dns-gate.example.com" # or DNSGATE_ENDPOINT

  auth {
    aws_web_identity {
      audience = "dns-gate"
    }
  }
}

# Other methods, exactly one per provider (plus optionally one CI method):
#   auth { token_file    = "/var/run/secrets/tokens/dns-gate" }
#   auth { token_command = ["my-oidc-helper", "--audience", "dns-gate"] }
#   auth { token         = var.gate_token }
# Without an auth block, DNSGATE_TOKEN or DNSGATE_TOKEN_FILE is used.
```

The IAM principal needs `sts:GetWebIdentityToken`, and the account must have IAM outbound identity
federation enabled. The gate trusts the account's issuer with the audience given here.

## Microsoft Entra ID

`azure_identity` tries, in order: environment credentials, AKS workload identity, managed identity, then the
Azure CLI login. With `client_id`, the chain is bound to that user-assigned identity.

```terraform
# A Microsoft Entra ID token for the gate application: environment
# credentials, AKS workload identity, managed identity, then the Azure CLI.
provider "dnsgate" {
  endpoint = "https://dns-gate.example.com"

  auth {
    azure_identity {
      scope = "api://dns-gate/.default"
      # tenant_id = "00000000-0000-0000-0000-000000000000"
      # client_id = "11111111-1111-1111-1111-111111111111" # user-assigned managed identity
    }
  }
}
```

## Azure DevOps OIDC

`azure_devops` requests the token Azure DevOps issues for a service connection (issuer
`https://vstoken.dev.azure.com/<organization id>`, subject `sc://<organization>/<project>/<service connection>`).
The service connection id is `service_connection_id` or `DNSGATE_ADO_SERVICE_CONNECTION_ID`; the job must map
`SYSTEM_ACCESSTOKEN` into the step environment.

```terraform
# In an Azure DevOps job, the OIDC token of a service connection; on a
# workstation (no SYSTEM_OIDCREQUESTURI), azure_identity with the Azure CLI
# login of the person running Terraform. Same configuration in both places.
provider "dnsgate" {
  endpoint = "https://dns-gate.example.com"

  auth {
    # service_connection_id defaults to DNSGATE_ADO_SERVICE_CONNECTION_ID,
    # for example from a variable group of the pipeline.
    azure_devops {}
    azure_identity {
      scope = "api://dns-gate/.default"
    }
  }
}
```

```yaml
# Azure DevOps: the job requests an OIDC token for the service connection
# trusted by the gate. The connection must be authorized for this pipeline,
# and System.AccessToken must be mapped into the step environment.
trigger: none

pool:
  vmImage: ubuntu-latest

variables:
  - group: dns-gate # DNSGATE_ADO_SERVICE_CONNECTION_ID, DNSGATE_ENDPOINT

steps:
  - script: |
      terraform init -input=false
      terraform apply -input=false -auto-approve
    displayName: terraform apply
    workingDirectory: dns
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
```

The audience of these tokens (`api://AzureADTokenExchange`) is shared by every service connection of the
organization: the gate must bind its issuer to the subjects of service connections dedicated to the gate.

## GitHub Actions

```terraform
# In a GitHub Actions job (permissions: id-token: write), the job's OIDC
# token with the gate's audience; elsewhere, the AWS identity of the caller.
provider "dnsgate" {
  endpoint = "https://dns-gate.example.com"

  auth {
    github_actions {
      audience = "dns-gate"
    }
    aws_web_identity {
      audience = "dns-gate"
    }
  }
}
```

```yaml
# GitHub Actions: the job may request an OIDC token (id-token: write); the
# github_actions method of the provider asks for one with the gate's audience.
name: dns
on:
  push:
    branches: [main]
permissions:
  contents: read
  id-token: write
jobs:
  apply:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - run: terraform init -input=false && terraform apply -input=false -auto-approve
        working-directory: dns
```
