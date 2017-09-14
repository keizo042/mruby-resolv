
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



##
##
## TESTING Resolv::DNS::Codec
##
##

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

  expected = [0x00, 0x42,  # Id
         w1,
         w2,
         0x00, 0x00, # QDCOUNT
         0x00, 0x00, # ANCOUNT
         0x00, 0x00, # NSCOUNT
         0x00, 0x00  # ARCOUNT
  ]

  assert_equal expected, c.encode(query)
end

assert("Resolv::DNS::Codec#decode") do
end

assert("Resolv::DNS::Codec#encode,decode Header") do
  expected = hdr_query
  actual = (c.decode (c.encode expected))
  assert_equal expected.header, actual.header
end

assert("Resolv::DNS::Codec#encode/decode Header|Question ") do
  expected = Resolv::DNS::Query.new(
    cliheader(1,0,0,0),
    [Resolv::DNS::Query::Question.new("google-public-dns-a.google.com.", 1,1)],
    [],
    [],
    [])
  actual = (c.decode (c.encode expected))
  assert_equal expected.header, actual.header
  assert_equal expected.questions, actual.questions
  assert_equal expected.answers, actual.answers
  assert_equal expected.authorities, actual.authorities
  assert_equal expected.additionals, actual.additionals
end

assert("Resolv::DNS::Codec#encode/decode Header|Answer") do
  expected = Resolv::DNS::Query.new(
    cliheader(0,1,0,0),
    [],
    [Resolv::DNS::Query::Answer.new("google-public-dns-a.google.com.",
                                    1,
                                    1,
                                    3600,
                                    4,
                                    [8,8,8,8])
  ],
   [],
   [])
  tmp = (c.encode expected)
  actual = (c.decode tmp)
  assert_equal expected.header, actual.header
end
