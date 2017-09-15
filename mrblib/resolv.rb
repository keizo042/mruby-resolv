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
    def initialize(af = Socket::AF_INET)
      @maxlen = 1280
      @socket =  UDPSocket.new af
      @port = 53
    end

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

    def send(query, host)
      raise ArgumentError, "expected #{Resolv::DNS::Query}" unless query.is_a?(Resolv::DNS::Query)
      raise ArgumentError, "expected hostname" if host.nil?
      payload = Resolv::DNS::Codec.new.encode(query).pack("c*")
      @socket.connect host, @port
      @socket.send payload, 0
    end

    def recv( maxlen = nil)
       len =(maxlen.nil? ? @maxlen : maxlen)
       payload = @socket.recv len
       DNS::Resolv::Codec.new.decode payload[0].unpack("c*");
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
        ArgumentError unless hdr.is_a?(Header) || q.is_a?(Question) || an.is_a?(Answer) || ns.is_a?(Authority)
        @header = hdr
        @questions = q.nil? ? [] : q
        @answers = an.nil? ? [] : an
        @authorities = ns.nil? ? [] : ns
        @additionals = ar.nil? ? [] : ar
      end

      def ==(rval)
        self.header == rval.header &&
          self.questions == rval.questions &&
          self.answers == rval.answers &&
          self.authorities == rval.authorities &&
          self.additionals == rval.additionals
      end

      class Header
        attr_reader :id, :qr, :opcode, :aa, :tc, :rd, :ra, :z, :rcode, :qdcount, :ancount, :nscount, :arcount

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
          @qr = (qr == 1) ? 1 : 0
          @opcode = opcode
          @aa = (aa == 1) ? 1 : 0
          @tc = (tc == 1) ? 1 : 0
          @rd = (rd == 1) ? 1 : 0
          @ra = (ra == 1) ? 1 : 0
          @rcode = rcode
          @qdcount = qdcount
          @ancount = ancount
          @nscount = nscount
          @arcount = arcount
        end

        def ==(rval)
          self.id  == rval.id && self.qr == rval.qr && self.opcode == rval.opcode && self.aa == rval.aa &&
            self.tc == rval.tc && self.rd == rval.rd && self.ra == rval.ra && self.rcode == rval.rcode 
            self.qdcount == rval.qdcount && self.ancount == rval.ancount && self.arcount == rval.arcount
        end
      end

      class RData
        attr_reader :name, :typ, :klass, :ttl, :rlength
        @name = ""
        @typ = 0
        @klass = 0
        @ttl = 0
        @rlength = 0
        @rdata = []

        def initialize(name, typ, klass, ttl, rlength, rdata)
          @name = name
          @typ = typ
          @klass = klass
          @ttl = ttl
          @rlength = rlength
          # TODO:  accepting Fixnum
          @rdata = rdata
        end
      end

        def ==(rval)
          self.name == rval.name && 
            self.typ == rval.typ &&
            self.klass == rval.klass && 
            self.ttl == rval.ttl &&
            self.rlength == rval.rlength && 
            self.rdata == rval.rdata
        end

        def rdata
          rdata.bytes.slice(0, self.rlength - 1) 
        end

      class Question
        attr_reader :qname, :qtype, :qklass
        @qname = nil
        @qtype = nil
        @qklass = nil

        def initialize(qname, qtype, qklass)
          raise ArgumentError.new, "expected (String, Fixnum, Fixnum)" unless qname.is_a?(String) || qtype.is_a?(Fixnum) || qklass.is_a?(Fixnum)
          @qname = qname
          @qtype = qtype
          @qklass = qklass
        end

        def ==(rval)
          self.qname == rval.qname &&
            self.qtype == rval.qtype &&
            self.qklass == rval.qklass 
        end
      end

      class Answer < Resolv::DNS::Query::RData; end
      class Authority < Resolv::DNS::Query::RData; end
      class Addtional < Resolv::DNS::Query::RData; end
    end

    class DomainName
      attr_reader :name
      def initialize(name = "")
        @name = name
      end

      def encode
         @name.split(".").each { |node| node.size.chr + node }.join("")
      end
    end


    class A ; end
    class AAAA; end
    class NS; end
    class MX; end
    class PTR; end
    class ANY; end
    class SOA; end
    class MX; end

    # Resource class indicate DNS Resource Record
    class Resource
      @rtype = 0

      #
      # DNS RR abstract "type" classes
      # 

      class A < Resolv::DNS::Resource
        @rtype = 1
      end

      class MX < Resolv::DNS::Resource
        @rtype = 15
      end

      class NS < Resolv::DNS::Resource
        @rtype = 2
      end

      class AAAA < Resolv::DNS::Resource
        @rtype = 25 
      end

      class PTR < Resolv::DNS::Resource
        @rtype = 12
      end

      class ANY < Resolv::DNS::Resource
        @rtype = 255
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
