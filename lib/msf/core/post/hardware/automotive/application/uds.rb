# -*- coding: binary -*-
module Msf
class Post
module Hardware
module Automotive
module Application

class UDS

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
end

end
end
end
end
end
