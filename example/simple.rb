# prepare data
hdr = Resolv::DNS::Query::Header.new(
    0x42,
    Resolv::DNS::Query::Header::QR::CLIENT,
    Resolv::DNS::Query::Header::OPCODE::QUERY,
    0,
    0,
    Resolv::DNS::Query::Header::RD::DESIRE,
    0,
    Resolv::DNS::Query::Header::RCODE::NoError,
    1, 0, 0, 0)

q = Resolv::DNS::Query.new(
  hdr,
  [Resolv::DNS::Query::Question.new("google.com", 1,1)],
    [],
    [],
    [])

dns = Resolv::DNS.new
dns.send(q, "8.8.8.8")
ret = dns.recv
p ret
# ret is a `Reolv::DNS::Query` as DNS Response, as you want
