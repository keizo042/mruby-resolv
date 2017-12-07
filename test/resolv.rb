
assert('Resolv Class') do
  assert_equal Resolv.class, Class
end

src_name = "google-public-dns.google.com"
src_address = "8.8.8.8"

assert('Resolv.getaddress') do
  expected = src_address
  actual = Resolv.getaddress(src_name)
  assert_equal expected, actual.address
end

assert('Resolv.getname') do
  assert_equal src_name, (Resolv.getname src_address).name
end

r = Resolv.new 

assert('Resolv.class') do
  assert_equal Resolv, r.class
end

assert('Resolv#getaddress') do
  assert_equal src_address, (r.getaddress src_name)
end

assert('Resolv#getname') do
  assert_equal src_name, (r.getname src_address)
end
