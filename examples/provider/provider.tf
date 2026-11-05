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
