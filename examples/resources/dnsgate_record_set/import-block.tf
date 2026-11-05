# Terraform or OpenTofu >= 1.5. GET /api/v1/zones/{zone}/terraform?team=<team>
# on the gate generates these blocks for every RRset of the team.
import {
  to = dnsgate_record_set.www
  id = "example.com/www/A"
}
