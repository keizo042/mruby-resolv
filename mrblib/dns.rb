# Resource class indicate DNS Resource Record
class Resolv
  class DNS
    def initialize(af = Socket::AF_INET)
      @maxlen = 1280
      @socket =  UDPSocket.new af
      # TODO: use /etc/resolv.conf
      @resolver = "8.8.8.8"
    end

    def self.open(*args)
      dns = DNS.new(*args)
      if block_given?
        yield(dns)
      else
        dns
      end
    end

    def getresource(name, typ)
      self.getresources(name, typ).first
    end

    def getresources(name, resource)
      query = Query.create_request(name, resource::TypeValue, resource::ClassValue)
      self.send(query, @resolver)
      self.recv.answers
    end

    def getname(addr)
      self.getnames(addr).first
    end

    def getnames(addr)
      self.getresources(addr, Resolv::DNS::Resource::IN::A)
    end

    def getaddress(name)
      self.getaddresses(name).first
    end

    def getaddresses(name)
      self.getresources(name, Resolv::DNS::Resource::IN::PTR)
    end

    def each_address(name, &proc)
      self.getaddresses(name).each do |a|
        proc.call(a.addr)
      end
      return
    end

    def each_name(addr, &proc)
      self.getnames(addr).each do |name|
        proc.call(n.name)
      end
      return
    end
  end
end
