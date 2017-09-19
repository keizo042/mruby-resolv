class Resolv
  class DNS
    class Config
      class OtherResolvError < StandardError; end

      def initialize
        raise NotImplementedError
      end
    end
  end
end
