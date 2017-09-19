assert("Resolv::DNS::Resource::DomainName#name") do
  name = "google.com"
  domainname = Resolv::DNS::Resource::DomainName.new(name)
  assert_equal name, domainname.name
end
