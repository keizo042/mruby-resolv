class Resolv
  class DNS
    class Resource
      TypeValue = 0
      #
      # DNS RR abstract "type" classes
      # 

      class MX < Resolv::DNS::Resource
        TypeValue = 15
      end

      class NS < Resolv::DNS::Resource
        TypeValue = 2
      end

      class PTR < Resolv::DNS::Resource
        TypeValue = 12
      end

      class ANY < Resolv::DNS::Resource
        TypeValue = 255
      end

      # CLASS INTERNET module
      module IN
        ClassValue = 1
        class A < Resolv::DNS::Resource
          TypeValue = 1
          ClassValue = IN::ClassValue
        end
        class AAAA < Resolv::DNS::Resource
          TypeValue = 28
          ClassValue = IN::ClassValue
        end
      end
    end
  end
end
