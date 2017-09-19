# TOP LEVEL NAMESPACE
class Resolv
  class ResolvError < StandardError; end
  DefaultResolver = DNS.new

  class << self
    def getaddress(name)
      DefaultResolver.getaddress(name)
    end

    def getaddresses(name)
      DefaultResolver.getaddresses(name)
    end

    def getname(addr)
      DefaultResolver.getname(addr)
    end

    def getnames(addr)
      DefaultResolver.getnames(addr)
    end

    def each_address(name)
      raise NotImplementedError
    end

    def each_name(addr)
      raise NotImplementedError
    end
  end

  #
  # instance
  #

  def initialize(resolvers= nil)
    @resolvers = resolvers.nil? ?  [DNS.new] : resolvers
  end

  def getaddress(name)
    @resolvers[0].getaddress(name)
  end

  def getaddresses(name)
    @resolvers[0].getaddresses(name)
  end

  def getname(addr)
    @resolvers[0].getname(name)
  end

  def getnames(addr)
    @resolvers[0].getnames(addr)
  end

  def each_address(name, &proc)
    @resolvers[0].each_address(name, proc)
  end

  def each_name(addr, &proc)
    @resolvers[0].each_name(addr, proc)
  end
end
