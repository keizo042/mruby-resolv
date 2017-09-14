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
  


ret = Resolv::DNS::Codec.new.encode(q)
p ret
p ret.size
ret.each { |i| print i.chr }
puts ""
