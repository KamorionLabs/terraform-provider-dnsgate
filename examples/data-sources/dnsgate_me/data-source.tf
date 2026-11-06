data "dnsgate_me" "this" {}

output "default_team" {
  value = data.dnsgate_me.this.default_team
}

output "teams" {
  value = data.dnsgate_me.this.teams
}
