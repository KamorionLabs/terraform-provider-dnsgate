# RRsets of the zone not yet owned by the gate: candidates for adoption.
data "dnsgate_record_sets" "foreign" {
  zone   = "example.com"
  status = "foreign"
}

# ACME challenges of a team.
data "dnsgate_record_sets" "acme" {
  zone  = "example.com"
  name  = "_acme-challenge.*"
  type  = "TXT"
  owner = "web"
}

output "to_adopt" {
  value = [for rs in data.dnsgate_record_sets.foreign.record_sets : rs.id]
}
