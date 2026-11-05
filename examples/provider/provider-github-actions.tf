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
