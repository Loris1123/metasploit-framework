# -*- coding: binary -*-
module Msf
class Post
module Hardware
module Automotive
module Transport

require 'msf/core/post/hardware/automotive/cantool'

  class ISOTP
    include Msf::Post::Hardware::Automotive::Cantool

    def initialize(bus, options)
      @bus = bus
    end

    def send(data)
      raise "Not yet implemented"
    end

    def send_data_and_wait_for_response(data)
      raise "Not yet implemented"
    end
  end

end
end
end
end
end
