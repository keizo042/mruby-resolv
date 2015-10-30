
assert('Resolv Class') do
  assert_equal Resolv.class, Class
end

assert('Resolv.getaddress') do
  assert_equal Resolv.getaddress "mruby.org" ,  "210.172.129.80"
end

assert('Resolv.getname') do
  assert_equal Resolv.getname "210.172.129.80" , "webforward.dnsv.jp"
end

r = Resolv.new 

assert('Resolv.class') do
  assert_equal r.class , Resolv
end

assert('Resolv obj.getaddress') do
  assert_equal r.getaddress "mruby.org" , "210.172.129.80"
end

assert('Resolv obj.getname') do
  assert_equal r.getname "210.172.129.80" , "webforward.dnsv.jp"
end



