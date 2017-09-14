hdr = Resolv::DNS::Query::Header.new(
    0x42,
    Resolv::DNS::Query::Header::QR::CLIENT,
    Resolv::DNS::Query::Header::OPCODE::QUERY,
    0,
    0,
    Resolv::DNS::Query::Header::RD::DESIRE,
    0,
    Resolv::DNS::Query::Header::RCODE::NoError,
    0, 1, 0, 0)
a = Resolv::DNS::Query::Answer.new(
  "google-public-dns-a.google.com",
  1,
  1,
  60 * 60,
  4,
  [8,8,8,8].map {|i| i.chr }.join
)
    

q = Resolv::DNS::Query.new(
  hdr,
    [],
    [a],
    [],
    [])
  


ret = Resolv::DNS::Codec.new.encode(q)
p ret
p ret.size
ret.each { |i| print i.chr }
puts ""
