# -*- coding: binary -*-
module Msf
class Post
module Hardware
module Automotive
module Application

class KWP2000

  # Service IDs
  START_DIAGNOSTIC_SESSION = "10"
  SECURITY_ACCESS = "27"
  READ_ECU_IDENTIFICATION = "1A"


  def initialize(client, bus, transport_protocol, options={})
    @client = client
    @bus = bus
    # Setting transport protocol
    case transport_protocol
    when "TP20"
      @client.automotive.set_transport_protocol(@bus, "TP20", options)
    else
      puts "UNKNOWN PROTOCOL"
    end
  end

  # Start a diagnostic session.
  # Param is manufacturer specific.
  # Returns the manufacturer specific response if successful
  # nil of not successful
  def start_diagnostic_session(param)
    response = @client.automotive.send_data_and_wait_for_response(@bus, "#{START_DIAGNOSTIC_SESSION}#{param}")
    if response[0] == "50"
      # Positive response. Return manufacturer specific response
      return response[1]
    else
      return nil
    end
  end

  #def read_data_by_common_identify(param)
  #  puts "Not supported yet"
  #end


  def read_ecu_identification(param)
    @client.automotive.send_data_and_wait_for_response(@bus, "#{READ_ECU_IDENTIFICATION}#{param}")
  end

  # Requesting the seed for security access.
  # Mode is the mode of access.
  #   "03", "05", "07"-"7F". See ISO 14230-3
  # Returns the seed in the following format["12", "34", "45", ...]
  # Nil of not successful
  def security_access_request_seed(mode)
    # First request seed
    response = @client.automotive.send_data_and_wait_for_response(@bus,"#{SECURITY_ACCESS}#{mode}")
    if response == nil
      puts "Error"
      return nil
    end
    if response[0] == "67" && response [1] == mode
      return response[2..-1]
    end
    return nil
  end

  # Sends the key for a security Access.
  # Mode is the mode of access. Typically it is one greater than when requesting the seed
  #    request_seed(03) -> send_key(04)
  # Key is the key to send in the following format: "AABBCCDDEEFF"
  #def security_access_send_key(mode, key)
  #  response = @tp.send_and_wait_for_response("#{SECURITY_ACCESS}#{mode}#{key}")
  #  return response
  #end


end

end
end
end
end
end
