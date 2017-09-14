
assert("Resolv::DNS::Codec is a Class") do
  assert_equal Class, Resolv::DNS::Codec.class
end


# make client header
def cliheader(qdcount, ancount,  nscount, adcount)
    Resolv::DNS::Query::Header.new(
      0x42,
      Resolv::DNS::Query::Header::QR::CLIENT,
      Resolv::DNS::Query::Header::OPCODE::QUERY,
      0, # aa selected by server
      0, # tc 
      Resolv::DNS::Query::Header::RD::DESIRE,
      0, # ra
      Resolv::DNS::Query::Header::RCODE::NoError,
      qdcount,
      ancount,
      nscount,
      adcount)
end

hdr_query = Resolv::DNS::Query.new(cliheader(0,0,0,0), [], [], [], [])

c = Resolv::DNS::Codec.new

assert("Resolv::DNS::Codec#encode Header") do
  query = hdr_query
  ret = c.encode(query)
  assert_equal Array, ret.class
  assert_equal 12, ret.size
  assert_equal Fixnum, ret[0].class
end

assert("Resolv::DNS::Codec#encode") do
  query = hdr_query
  w1=    ((Resolv::DNS::Query::Header::QR::CLIENT << 7)  | 
          (Resolv::DNS::Query::Header::OPCODE::QUERY << 3) | 
          0  | # AA 
          0  | # TC 
          Resolv::DNS::Query::Header::RD::DESIRE)
  w2 =  (0 |  # RA
         0 |  # Z
         Resolv::DNS::Query::Header::RCODE::NoError)

  res = [0x00, 0x42,  # Id
         w1,
         w2,
         0x00, 0x00, # QDCOUNT
         0x00, 0x00, # ANCOUNT
         0x00, 0x00, # NSCOUNT
         0x00, 0x00  # ARCOUNT
  ]
  assert_equal res, c.encode(query)
end

assert("Resolv::DNS::Codec#decode") do
end

assert("Resolv::DNS::Codec#encode,decode Header") do
  query = hdr_query
  assert_equal query, (c.decode (c.encode query))
end

assert("Resolv::DNS::Codec#encode/decode Header|Question ") do
  query = Resolv::DNS::Query.new(
    cliheader(1,0,0,0),
    [Resolv::DNS::Query::Question.new("google-public-dns-a.google.com.", 1,1)],
    [],
    [],
    [])
  assert_equal query, (c.decode (c.encode query))
end

assert("Resolv::DNS::Codec#encode/decode Header|Answer ") do
  query = Resolv::DNS::Query.new(
    cliheader(0,1,0,0),
    [],
    [Resolv::DNS::Query::Answer.new("google-public-dns-a.google.com.",
                                    1,
                                    1,
                                    86400,
                                    4,
                                    0x03030303) # 08888
  ],
   [],
   [])

  assert_equal query, (c.decode (c.encode query))
end

assert("Resolv::DNS::Codec#encode/decode Header ") do
  query = Resolv::DNS::Query.new(
    cliheader(0,0,0,0),
    [],
    [],
    [],
    [])
  assert_equal query, (c.decode (c.encode query))
end

