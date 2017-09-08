
assert('Resolv Class') do
  assert_equal Resolv.class, Class
end

assert('Resolv.getaddress') do
  assert_equal (Resolv.getaddress "google-public-dns-a.google.com") ,  "8.8.8.8"
end

assert('Resolv.getname') do
  assert_equal (Resolv.getname "8.8.8.8"), "google-public-dns-a.google.com")
end

r = Resolv.new 

assert('Resolv.class') do
  assert_equal r.class , Resolv
end

assert('Resolv#getaddress') do
  assert_equal (r.getaddress "google-public-dns-a.google.com") , "8.8.8.8"
end

assert('Resolv#getname') do
  assert_equal (r.getname "8.8.8.8"), "google-public-dns-a.google.com", 
end


