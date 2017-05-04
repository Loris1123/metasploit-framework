# -*- coding: binary -*-
module Msf
class Post
module Hardware
module Automotive
module Application

class KWP2000

  # Service IDs
  START_DIAGNOSTIC_SESSION = "10"

  def initialize(transport_protocol)
    @tp = transport_protocol
  end

  # Start a diagnostic session.
  # Param is manufacturer specific.
  # Returns the manufacturer specific response if successful
  # nil of not successful
  def start_diagnostic_session(param="00")
    response = @tp.send_and_wait_for_response("#{START_DIAGNOSTIC_SESSION}#{param}")
    if response[0] == "50"
      # Positive response. Return manufacturer specific response
      puts("KWP2000: Start Diagnostic successful")
      return response[1]
    else
      puts("KWP2000: Start Diagnostic failed")
      return nil
    end
  end

  def security_access(code)
    # First request seed
    #@tp.send_and_wait_for_response("")
    # Then send code
  end




end

end
end
end
end
end
