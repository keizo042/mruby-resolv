assert("Resolv::DNS is a Class") do
  assert_equal Resolv::DNS.class, Class
end

dns = Resolv::DNS.new


assert("Resolv::DNS#getresource") do
  dns.getresource nil, nil
end

assert("Resolv::DNS#getresources") do
  dns.getresources nil, nil 
end

assert("Resolv::DNS#getname") do
  assert_equal (dns.getname "8.8.8.8"), "google-public-dns-a.google.com"

end

assert("Resolv::DNS#getnames") do
  assert_equal (dns.getname "8.8.8.8"), [""]
end

assert("Resolv::DNS#getaddress") do
  assert_equal (dns.getaddress ""), ""
end

assert("Resolv::DNS#getaddresses") do
  assert_equal (dns.getaddresses "") []
end

assert("Resolv::DNS#each_name") do
end

assert("Resolv::DNS#each_address") do
end

assert("Resolv::DSN#timeout=") do
end
