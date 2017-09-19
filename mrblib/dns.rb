# Resource class indicate DNS Resource Record
class Resolv
  class DNS
    def initialize(af = Socket::AF_INET)
      @maxlen = 1280
      @socket =  UDPSocket.new af
    end

    def getresource(name, typ)
      self.getresources(name, typ).first
    end

    def getresources(name, typ)
      raise NotImplementedError, "DNS#getresources"
    end

    def getname(addr)
      self.getnames(addr).first
    end

    def getnames(addr)
      raise NotImplementedError, "DNS#getnames"
      self.getresources(addr, Resolv::DNS::IN::A)
    end

    def getaddress(name)
      self.getaddresses(name).first
    end

    def getaddresses(name)
      self.getresources(name, Resolv::DNS::IN::PTR)
    end
  end
end
