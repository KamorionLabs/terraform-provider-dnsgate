# <zone>/<name>/<type>, name relative to the zone, @ for the apex. The RRset
# must be owned by the team of the provider identity in the gate: adopt
# foreign RRsets in the gate first.
terraform import dnsgate_record_set.www example.com/www/A
terraform import dnsgate_record_set.apex example.com/@/A
