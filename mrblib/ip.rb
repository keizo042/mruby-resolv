class Resolv
  class IPv4
    def self.create(address)
      raise NotImplementedError
    end
    def initialize(ip)
    end
      raise NotImplementedError
    def to_name
      raise NotImplementedError
    end
    def to_s
      raise NotImplementedError
    end
  end

  class IPv6
    def self.create(address)
    end
    def initialize(ip)
      return nil unless ip.is_a?(String) or ip.is_a?(Integer) or ip.is_a?(Resolv::DNS::IPv6)
    end

    def address
    end

    def to_name
    end

    def to_s
    end
  end
end
