class Resolv
  class DNS
    class Resource
      TypeValue = 0

      class MX < Resolv::DNS::Resource
        TypeValue = 15
      end

      class NS < Resolv::DNS::Resource
        TypeValue = 2
      end

      class TXT < Resolv::DNS::Resource
        def initialize
          raise NotImplementedError
        end

        def data
          raise NotImplementedError
        end

        def string
          raise NotImplementedError
        end
      end

      class PTR < Resolv::DNS::Resource
        TypeValue = 12
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
        [NS, MX, PTR, TXT, ANY].each do |s|
	    c = Class.new(s)
	    c.const_set(:TypeValue, s::TypeValue)
	    c.const_set(:ClassValue, ClassValue)
	    ClassHash[[s::TypeValue, ClassValue]] = c
	    self.const_set(s.name.sub(/.*::/, ''), c)
        end

        #
        # Internet Resource Records 
        #
        class A < Resolv::DNS::Resource
          TypeValue = 1
          ClassValue = IN::ClassValue

          def initialize(address)
            raise NotImplementedError, "A#new"
          end

          def address
            raise NotImplementedError
          end
        end

        class AAAA < Resolv::DNS::Resource
          TypeValue = 28
          ClassValue = IN::ClassValue

          def initialize(address)
            raise NotImplementedError, "AAAA#new"
          end
        end

        class  SRV < Resolv::DNS::Resource
          TypeValue = 33
          ClassValue = IN::ClassValue
          def initialize
            raise NotImplementedError
          end
        end
      end
    end
  end
end
