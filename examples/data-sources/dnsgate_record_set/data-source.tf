data "dnsgate_record_set" "mx" {
  zone = "example.com"
  name = "@"
  type = "MX"
}

output "mx_owner" {
  value = data.dnsgate_record_set.mx.owner
}
