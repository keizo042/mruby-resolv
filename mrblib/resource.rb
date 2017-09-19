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

      class PTR < Resolv::DNS::Resource
        TypeValue = 12
      end

      class OPT < Resolv::DNS::Resource
        TypeValue = 41
      end

      class ANY < Resolv::DNS::Resource
        TypeValue = 255
      end

      # CLASS INTERNET module
      module IN
        ClassValue = 1
        #
        # Common Resource Record Definition
        #
        [NS, MX, PTR, ANY].each do
        end
        class A < Resolv::DNS::Resource
          TypeValue = 1
          ClassValue = IN::ClassValue
        end
        class AAAA < Resolv::DNS::Resource
          TypeValue = 28
          ClassValue = IN::ClassValue
        end

        class  SRV < Resolv::DNS::Resource
          TypeValue = 33
          ClassValue = IN::ClassValue
        end

        class WKS < Resolv::DNS::Resource
          TypeValue = 11
          ClassValue = IN::ClassValue
        end
      end
    end
  end
end
