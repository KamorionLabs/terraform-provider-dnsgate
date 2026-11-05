data "dnsgate_zones" "route53" {
  dns_provider = "route53"
}

output "route53_zones" {
  value = data.dnsgate_zones.route53.names
}
