#!/usr/bin/env ruby
# Send test requests through the proxy, with the different test certificates,
# and check the status of each answer.
#
# The script needs a running `server` and a running `proxy`, with the policy
# file `policies.yaml` of this repository. It needs the files of
# `scripts/gen-dev-certs.sh`. To see the audit events, look at STDOUT of the proxy.
#
# Usage: scripts/send-test-requests.rb
# Variables: PROXY_ADDR (default 127.0.0.1:8443), SERVER_ADDR (default 127.0.0.1:9000)
# Exit code: 0 if every answer has the expected status, 1 if not, 2 if the
# setup is not ready (a program is not running, or a certificate is missing).

require "net/http"
require "openssl"
require "socket"

ROOT = File.expand_path("..", __dir__)
CERTS = File.join(ROOT, "dev-certs")
PROXY_ADDR = ENV.fetch("PROXY_ADDR", "127.0.0.1:8443")
SERVER_ADDR = ENV.fetch("SERVER_ADDR", "127.0.0.1:9000")

def listening?(addr)
  host, port = addr.split(":")
  Socket.tcp(host, port.to_i, connect_timeout: 2, &:close)
  true
rescue SystemCallError, SocketError
  false
end

def abort_setup(message)
  warn message
  exit 2
end

# Send one request. Print the result. Return true if the status is expected.
# expected: the status that we expect. 0 means no HTTP answer (the TLS handshake fails).
# cert: the name of the certificate in dev-certs/ (without `.pem`), or "none".
def send_request(expected, cert, method, path)
  host, port = PROXY_ADDR.split(":")
  options = { use_ssl: true, ca_file: File.join(CERTS, "ca.pem"), open_timeout: 5, read_timeout: 5 }
  unless cert == "none"
    options[:cert] = OpenSSL::X509::Certificate.new(File.read(File.join(CERTS, "#{cert}.pem")))
    options[:key] = OpenSSL::PKey.read(File.read(File.join(CERTS, "#{cert}.key")))
  end
  error = nil
  status =
    begin
      # Net::HTTP sends the path as it is. It does not remove `..`.
      Net::HTTP.start(host, port.to_i, **options) do |http|
        http.send_request(method, path, method == "POST" ? "" : nil).code.to_i
      end
    rescue StandardError => e # With TLS 1.3, a rejected client certificate shows up here.
      error = "#{e.class}: #{e.message}"
      0
    end

  ok = status == expected
  puts format("%-4s %03d  %-16s %-5s %-44s (expected %03d)",
              ok ? "ok" : "FAIL", status, cert, method, path, expected)
  puts "       #{error}" if !ok && error # A failure that we did not expect: show why.
  ok
end

# Each group: a title, the status that we expect, then [certificate, method, path].
GROUPS = [
  ["Allowed by the policy:", 200, [
    ["payment-agent", "POST", "/payments"],
    ["reporting-agent", "GET", "/reports/1"],
    ["reporting-agent", "GET", "/reports/1?token=not-in-the-audit-event"]
  ]],
  ["Denied by the policy (403):", 403, [
    ["payment-agent", "GET", "/payments"],
    ["payment-agent", "POST", "/reports/1"],
    ["reporting-agent", "POST", "/payments"],
    ["reporting-agent", "GET", "/reports"]
  ]],
  ["Path that is not valid (400):", 400, [
    ["payment-agent", "POST", "/payments//x"],
    ["reporting-agent", "GET", "/reports/%2e%2e/payments"],
    ["reporting-agent", "GET", "/reports/../payments"]
  ]],
  ["No identity (401):", 401, [
    ["no-uri-agent", "POST", "/payments"]
  ]],
  ["TLS handshake fails (no answer):", 0, [
    ["none", "POST", "/payments"],
    ["untrusted-agent", "POST", "/payments"],
    ["expired-agent", "POST", "/payments"]
  ]]
].freeze

unless system(File.join(ROOT, "scripts", "gen-dev-certs.sh"), "check", out: File::NULL, err: File::NULL)
  abort_setup "A test certificate is missing or expired. Run: scripts/gen-dev-certs.sh"
end
abort_setup "The server is not running on #{SERVER_ADDR}. Start it: cargo run -- server" unless listening?(SERVER_ADDR)
abort_setup "The proxy is not running on #{PROXY_ADDR}. Start it: cargo run -- proxy" unless listening?(PROXY_ADDR)

puts "Proxy: https://#{PROXY_ADDR}  Server: http://#{SERVER_ADDR}\n\n"
failures = 0
GROUPS.each do |title, expected, requests|
  puts title
  requests.each { |request| failures += 1 unless send_request(expected, *request) }
end

puts
if failures.positive?
  puts "#{failures} request(s) did not get the expected status."
  exit 1
end
puts "Every request got the expected status."
puts "The proxy wrote one audit event for each request that passed the handshake."
