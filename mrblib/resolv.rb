# TOP LEVEL NAMESPACE
class Resolv
  class ResolvError < StandardError; end

  class << self
    def getaddress(name)
      raise NotImplementedError
    end

    def getaddresses(name)
      raise NotImplementedError
    end

    def getname(addr)
      raise NotImplementedError
    end

    def getnames(addr)
      raise NotImplementedError
    end

    def each_address(name)
      raise NotImplementedError
    end

    def each_name(addr)
      raise NotImplementedError
    end
  end

  def getaddress(name)
    raise NotImplementedError
  end

  def getaddresses(name)
    raise NotImplementedError
  end

  def getname(addr)
    raise NotImplementedError
  end

  def getnames(addr)
    raise NotImplementedError
  end

  def each_address(addr)
    raise NotImplementedError
  end

  def each_name(addr)
    raise NotImplementedError
  end
end
