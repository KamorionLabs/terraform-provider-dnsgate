# go.example.com answers HTTP requests with a permanent redirect.
resource "dnsgate_url_forward" "go" {
  zone = "example.com"
  name = "go"
  type = "301"
  url  = "https://www.example.com/landing"
}

# The apex shows the shop in a frame, the browser keeping example.com in its
# address bar. title, keywords and description are for frame forwards only.
resource "dnsgate_url_forward" "apex" {
  zone        = "example.com"
  name        = "@"
  type        = "frame"
  url         = "https://shop.example.net/"
  title       = "Example shop"
  keywords    = "shop, example"
  description = "The example shop"
}

# Fail the apply rather than create a forward that answers plain HTTP only:
# the domain must have an HTTPS redirect subscription at the DNS provider.
resource "dnsgate_url_forward" "promo" {
  zone          = "example.com"
  name          = "promo"
  type          = "302"
  url           = "https://www.example.com/promo"
  require_https = true
  team          = "web"
}
