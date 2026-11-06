data "dnsgate_teams" "declared" {
  kind = "declared"
}

output "teams" {
  value = { for t in data.dnsgate_teams.declared.teams : t.name => t.description }
}
