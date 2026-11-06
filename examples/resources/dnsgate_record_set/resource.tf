resource "dnsgate_record_set" "www" {
  zone   = "example.com"
  name   = "www"
  type   = "A"
  ttl    = 300
  values = ["192.0.2.10", "192.0.2.11"]
}

# Target names may be written with or without trailing dot.
resource "dnsgate_record_set" "blog" {
  zone   = "example.com"
  name   = "blog"
  type   = "CNAME"
  ttl    = 3600
  values = ["example.github.io."]
}

resource "dnsgate_record_set" "mx" {
  zone   = "example.com"
  name   = "@"
  type   = "MX"
  ttl    = 3600
  values = ["10 mx1.example.net.", "20 mx2.example.net."]
}

# TXT values are written unquoted, at any length: the gate splits them in
# 255-byte strings for the DNS provider, and the provider compares the
# concatenated text, so a DKIM key never shows a perpetual diff.
resource "dnsgate_record_set" "dkim" {
  zone   = "example.com"
  name   = "selector1._domainkey"
  type   = "TXT"
  ttl    = 3600
  values = ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx3ylhXuPNbGQvJxZ0sO4QbmX0N1F7y5Ul6UqGmpTzXz4rXfiwR3Npx6lfsY3gbDpzaD8F1yH0X1H1o8xG5Wkzv7QZx9Vq1e3rT3c8D2yQyNnQ2vDgJmB6V8bTzQ4m8yq0XhWf6j1nO7mI2rQGqS2lQe0uW7nHkR5t2cP0yVwF9eL3bJz8aKpQ4sR1mN6vT0xYiUoE3wZ2gH7jK9lF5dC8bA1nM4qW6eR0tY2uI9oP3aS5dF7gH1jK3lZ6xC8vB0nM2qW4eR6tY8uI0oP2aS4dF6gH8jK0lZ2xC4vB6nM8qW0eR2tY4uI6oP8aS0dF2gH4jK6lZ8xC0vB2nM4qWIDAQAB"]
}

# Alias to a CloudFront distribution (Route53 zones): no ttl, no values.
resource "dnsgate_record_set" "apex" {
  zone = "example.com"
  name = "@"
  type = "A"

  alias {
    name                   = "d111111abcdef8.cloudfront.net"
    zone_id                = "Z2FDTNDATAQYW2" # CloudFront
    evaluate_target_health = false
  }
}

# An identity acting for several teams (for example a shared pipeline)
# creates the record set for one of them. The plan fails unless the
# identity is a member of that team.
resource "dnsgate_record_set" "shop" {
  zone   = "example.com"
  name   = "shop"
  type   = "CNAME"
  ttl    = 300
  values = ["shop.example.net."]
  team   = "web"
}
