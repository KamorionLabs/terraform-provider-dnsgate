# <zone>/<name>, name relative to the zone, @ for the apex. The forward must
# be owned by the team of the provider identity in the gate: adopt foreign
# forwards in the gate first.
terraform import dnsgate_url_forward.go example.com/go
terraform import dnsgate_url_forward.apex example.com/@
