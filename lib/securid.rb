require 'securid/securid'

module RSA
  module SecurID

    # Manages a single authentication session against the RSA ACE server. Handles the various life cycle
    # events that may occur, such as token resynchronization and pin changes. Includes a test mode that can
    # simulate various responses when an ACE server is not present (for example during local development).
    # Instances of this class should not be reused unless the RSA flow (and this documentation) indicates
    # otherwise (for example, you can issue an {#authenticate} call after a successful {#change_pin} call).
    #
    # This class assumes you have an understanding of the RSA authentication flow. Timeouts on state
    # transitions are enforced by the server, and are not documented here as they may change between ACE
    # releases.
    #
    # In test mode, this class will send no network traffic and not talk to the RSA agent. The RSA SDK
    # libraries do not even need to be present, just the header files. In the normal mode, the server
    # configuration is imported by the agent directly.
    class Session

      # Returns the current state of the session, which is one of {AUTHENTICATED}, {DENIED},
      # {MUST_CHANGE_PIN}, {MUST_RESYNCHRONIZE}, or {UNSTARTED}.
      attr_reader :status

      AUTHENTICATED = :authenticated
      DENIED = :denied
      MUST_CHANGE_PIN = :must_change_pin
      MUST_RESYNCHRONIZE = :must_resynchronize
      UNSTARTED = nil

      # @return [Boolean] +true+ if the session is in the {MUST_RESYNCHRONIZE} state, +false+ otherwise.
      # Checks if the session is in the {MUST_RESYNCHRONIZE} state.
      def resynchronize?
        @status == MUST_RESYNCHRONIZE
      end

      # Checks if the session is in the {MUST_CHANGE_PIN} state.
      # @return [Boolean] +true+ if the session is in the {MUST_CHANGE_PIN} state, +false+ otherwise.
      def change_pin?
        @status == MUST_CHANGE_PIN
      end

      # Checks if the session is in the {AUTHENTICATED} state.
      # @return [Boolean] +true+ if the session is in the {AUTHENTICATED} state, +false+ otherwise.
      def authenticated?
        @status == AUTHENTICATED
      end

      # Checks if the session is in the {DENIED} state.
      # @return [Boolean] +true+ if the session is in the {DENIED} state, +false+ otherwise.
      def denied?
        @status == DENIED
      end
    end
  end
end
