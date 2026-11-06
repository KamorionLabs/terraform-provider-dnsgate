data "dnsgate_team" "web" {
  name = "web"
}

output "web_rrsets_per_zone" {
  value = { for o in data.dnsgate_team.web.owned : o.zone => o.rrsets }
}

output "web_pending_transfers" {
  value = [for t in data.dnsgate_team.web.pending_transfers : "${t.from_team} -> ${t.to_team} (${t.zone})"]
}
