# TOP LEVEL NAMESPACE
class Resolv
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

  # DNS resolver
  class DNS

    def getresources(name, typ)
      raise NotImplementedError
    end

    def getresource(name, typ)
      raise NotImplementedError
    end

    def getname(addr)
      raise NotImplementedError
    end

    def getnames(addr)
      raise NotImplementedError
    end

    def getaddress(name)
      raise NotImplementedError
    end

    def getaddresses(name)
      raise NotImplementedError
    end

    class IPv4
      @octets = []

      def initialize(ip)
      end
    end

    class IPv6
      @octets = []
      def to_s
      end

      def string2octets ip
      end

      def int2octets ip
      end
      
      def initialize(ip)
        return nil unless ip.is_a?(String) or ip.is_a?(Integer) or ip.is_a?(Resolv::DNS::IPv6)
      end
    end

    class Query
      attr_accessor :header, :questions, :answers, :authorities, :additionals

      def initialize(hdr, q, an, ns, ar)
        @header = hdr
        @questions = q.nil? ? [] : q
        @answers = an.nil? ? [] : an
        @authorities = ns.nil? ? [] : ns
        @addtionals = ar.nil? ? [] : ar
      end

      class Header

        @id = 0
        @qr = 0
        @opcode = 0
        @aa = 0
        @tc = 0
        @rd = 0
        @ra = 0
        @z = 0
        @rcode = 0
        @qdcount = 0
        @ancount = 0
        @nscount = 0
        @arcount = 0

        module QR
          CLIENT = 0
          SERVER = 1
        end
        module OPCODE
          QUERY = 0
          INVERSE = 1
          STATUS = 2
        end
        module AA
          RECURSIVE = 0
          AUTHORATIVE = 1
        end
        module TC
          NOTRUNCATE = 0
          TRUNCATE = 1
        end

        module RD
          NODESIRE = 0
          DESIRE = 1
        end

        module RA
          NOAVALIABLE = 0 
          AVALIABLE = 1
        end

        module RCODE
          NoError = 0
          FormatError = 1
          ServerError = 2
          NxDomainError = 3
          NotImplementedError = 4
          DeninedError = 5
        end
        
        def initialize(id, qr, opcode, aa, tc, rd, ra, rcode, qdcount, ancount, nscount, arcount)
          # TODO: value validation
          @id = id
          @qr = qr
          @opcode = opcode
          @aa = aa
          @tc = tc
          @rd = rd
          @ra = ra
          @rcode = rcode
          @qdcount = qdcount
          @ancount = ancount
          @nscount = nscount
          @arcount = arcount
        end
      end


      class RData
        @name = ""
        @typ = 0
        @klass = 0
        @ttl = 0
        @rlength = 0
        @rdata = nil

        def initialize(name, typ, klass, ttl ,rlength, rdata)
          @name = name
          @typ = typ
          @klass = klass
          @ttl = ttl
          @rlength = rlength
          # TODO:  accepting Fixnum
          @rdata = rdata
        end
      end

      class Question
        @qname = nil
        @qtype = nil
        @qklass = nil

        def initialize(qname, qtype, qklass)
          @qname = qname
          @qtype = qtype
          @qklass = qklass
        end
      end

      class Answer < Resolv::DNS::Query::RData; end
      class Autority < Resolv::DNS::Query::RData; end
      class Addtional < Resolv::DNS::Query::RData; end

    end

    class DomainName
      @data = nil

      def initialize(name)
        @data = name
      end

      def encode
        @data
      end
    end


    class A ; end
    class AAAA; end
    class NS; end
    class MX; end
    class PTR; end
    class ANY; end
    class MX; end

    class Resource
      @rtype = 0

      #
      # DNS RR abstract "type" classes
      # 

      class A < Resolv::DNS::Resource
        @rtype = 1
      end

      class MX
        @rtype = 15
      end

      class NS
      end

      class AAAA
      end

      class PTR
      end

      class ANY
      end

      # CLASS INTERNET module
      module IN
        @rklass = 1
        class A < Resolv::DNS::A
          include Resolv::DNS::Resource::IN
        end

        class MX < Resolv::DNS::MX
          include Resolv::DNS::Resource::IN
        end

        class NS < Resolv::DNS::NS
          include Resolv::DNS::Resource::IN
        end

        class AAAA < Resolv::DNS::AAAA
          include Resolv::DNS::Resource::IN
        end

        class ANY < Resolv::DNS::ANY
          include Resolv::DNS::Resource::IN
        end
      end
    end
  end
end
