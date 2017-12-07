class Resolv
  class DNS
    class Resource
      TypeValue = 0

      class DomainName < Resolv::DNS::Resource
        attr_reader :name
        def initialize(name)
          @name= name
        end
      end

      class MX < Resolv::DNS::Resource
        TypeValue = 15
        attr_reader :preference, :exchange

        def initialize(preference, exchange)
          @preference = preference
          @exchange = exchange
        end
      end

      class CNAME < Resolv::DNS::DomainName
        TypeValue = 5
        attr_reader :cname

        def initialize(cname)
          @cname = cname
        end

        def name
          @cname
        end
      end

      class NS < DNS::Resource::DomainName
        TypeValue = 2

        def initialize(nsdname)
          @nsdname = nsdname
        end

        def name
          @nsdname
        end
      end

      class TXT < Resolv::DNS::Resource
        TypeValue = 16
        def initialize(data)
          @data = data.split("\n")
        end

        def data
          @data.first
        end

        def strings
          @data
        end
      end

      class PTR < Resolv::DNS::DomainName
        TypeValue = 12
        attr_reader :ptrdomain
        def initialize(ptrdomain)
          @ptrdomain = ptrdomain
        end
        def name
          @ptrdomain
        end
      end

      class SOA < Resolv::DNS::Resource
        TypeValue = 6
        attr_reader :mname, :rname, :serial, :refresh, :retry, :expire, :minimum

        def initialize(mname, rname, serial, refresh, retry_, expire, minimum)
          @mname = mname
          @rname = serial
          @refresh = redresh
          @retry = retry_
          @expire = expire
          @minimum = minimum
        end

        def retry
          @retry_
        end
      end

      class OPT < Resolv::DNS::Resource
        TypeValue = 41
      end

      class ANY < Resolv::DNS::Resource
        TypeValue = 255
      end

      # Class Internet
      module IN
        ClassValue = 1
        #
        # Common Resource Records
        #
        class NS < Resource::NS
          ClassValue = IN::ClassValue
        end
        class CNAME < Resource::CNAME
          ClassValue= IN::ClassValue
        end
        class MX < Resource::MX
          ClassValue = IN::ClassValue

        end
        class PTR < Resource::PTR
          ClassValue = IN::ClassValue
        end
        class TXT < Resource::TXT
          ClassValue = IN::ClassValue
        end
        class ANY < Resource::ANY
          ClassValue = IN::ClassValue
        end

        #
        # Internet Resource Records 
        #
        class A < Resolv::DNS::Resource
          TypeValue = 1
          ClassValue = IN::ClassValue
          attr_reader :address

          def initialize(address)
            @address = address
          end
        end

        class AAAA < Resolv::DNS::Resource
          TypeValue = 28
          ClassValue = IN::ClassValue
          attr_reader :address

          def initialize(address)
            @address = address
          end
        end

        class  SRV < Resolv::DNS::Resource
          TypeValue = 33
          ClassValue = IN::ClassValue
          attr_reader :priority, :weight, :port, :target
          def initialize(priority, weight, port, target)
            @priority = priority
            @weight =  weight
            @port = port
            @target = target
          end
        end
      end
    end
  end
end
