assert("Resolv::DNS::Resource::DomainName#name") do
  name = "google.com"
  domainname = Resolv::DNS::Resource::DomainName.new(name)
  asset_equal name, domainname.name
end
