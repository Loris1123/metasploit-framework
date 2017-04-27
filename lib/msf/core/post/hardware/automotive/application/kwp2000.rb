# -*- coding: binary -*-
module Msf
class Post
module Hardware
module Automotive
module Application

class KWP2000

  def initialize(transport_protocol)
    @tp = transport_protocol
  end

  # Invalid request to test the function of the underlying transport protocol
  def test_request()
    @tp.send("112233445566778899AA")
  end
end

end
end
end
end
end
