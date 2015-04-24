require 'securid/securid'

module RSA
  module SecurID
    class Session
      attr_reader :status

      AUTHENTICATED = :authenticated
      DENIED = :denied
      MUST_CHANGE_PIN = :must_change_pin
      MUST_RESYNCHRONIZE = :must_resynchronize

      def resynchronize?
        @status == MUST_RESYNCHRONIZE
      end

      def change_pin?
        @status == MUST_CHANGE_PIN
      end

      def authenticated?
        @status == AUTHENTICATED
      end

      def denied?
        @status == AUTHENTICATED
      end
    end
  end
end
