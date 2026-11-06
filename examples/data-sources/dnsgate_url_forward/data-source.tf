data "dnsgate_url_forward" "go" {
  zone = "example.com"
  name = "go"
}

output "go_target" {
  value = data.dnsgate_url_forward.go.url
}

output "forwards_answer_https" {
  value = contains(["active", "no_forward"], data.dnsgate_url_forward.go.https_status)
}
