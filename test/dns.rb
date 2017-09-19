assert("Resolv::DNS is a Class") do
  assert_equal Resolv::DNS.class, Class
end

dns = Resolv::DNS.new
src_name = "google-public-dns-a.google.com"
src_address = "8.8.8.8"


assert("Resolv::DNS#getresource") do
  expected = Resolv::DNS::Resource::IN::A.new(src_address)
  actual = dns.getresource( src_name, Resolv::DNS::Resource::IN::A)

  assert_equal expected, actual
end

assert("Resolv::DNS#getresources") do
  expected = Resolv::DNS::Resource::IN::A.new(src_address)
  actual = dns.getresources( src_name, Resolv::DNS::Resource::IN::A)

  assert_equal expected, actual.first
end

assert("Resolv::DNS#getname") do
  expected = src_name
  actual = dns.getname(src_address)

  assert_equal src_name, actual.name
end

assert("Resolv::DNS#getnames") do
  expected = src_name
  actual = dns.getnames("8.8.8.8").first

  assert_not_equal nil, actual
  assert_equal src_name, actual.name
end

assert("Resolv::DNS#getaddress") do
  expected = src_address
  actual = dns.getaddress(src_name)
  assert_equal expected, actual.address
end

assert("Resolv::DNS#getaddresses") do
  expected =  src_address
  actual = (dns.getaddresses src_name).first

  assert_not_equal nil, actual
  assert_equal expected, actual.address
end

assert("Resolv::DNS#each_name") do
  actual = []
end

assert("Resolv::DNS#each_address") do
  actual = []
end

assert("Resolv::DSN#timeout=") do
  actual = []
end
