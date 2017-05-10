# -*- coding: binary -*-
module Msf
class Post
module Hardware
module Automotive
module Cantool

  require 'pty'

  # candumbs contain the output of candump when listening for a specific package of the following format:
  #{"ID1" => [frame1, frame2,...], "ID2" => [frame2, frame3,..]}
  @@candumps = {}

  # Sends a raw CAN packet
  # bus = string
  # id = hex ID
  # data = string of up to 8 hex bytes
  def cansend(bus, id, data)
    result = {}
    result["Success"] = false
    id = id.to_i(16).to_s(16)  # Clean up the HEX
    bytes = data.scan(/../)  # Break up data string into 2 char (byte) chunks
    if bytes.size > 8
      print_error("Data section can only contain a max of 8 bytes")
      return result
    end
    `which cansend`
    unless $?.success?
      print_error("cansend from can-utils not found in path")
      return result
    end
    system("cansend #{bus} #{id}##{bytes.join}")
    result["Success"] = true if $?.success?
    result
  end

  # Returns <count> numbers of CAN packages from the buffered frames of ID <id>
  # from @candumps
  def get_buffered_packages(id, count)
    if @@candumps[id.to_s].nil?
      {"status" => "No buffer of id #{id} available"}
    else
      @@candumps[id.to_s].shift(count.to_i)
    end
  end

  # Adds the received packages of the given ID to @candumps
  # TODO: Check if listener for ID is already running for ID.
  # TODO: maybe add a custom identifier, to allow multiple listeners for an ID
  # TODO: Add support for multiple buses
  def candump_listener(bus, id)
    # Run the command in background and continiously grap the output
    # See http://stackoverflow.com/questions/1154846/continuously-read-from-stdout-of-external-process-in-ruby
    @@candumps[id.to_s] = [] if @@candumps[id.to_s].nil?

    command = "candump #{bus},#{id}:FFF"
    Thread.new do
      PTY.spawn(command) do |stdout, stdin, pid|
        begin
          stdout.each{ |l| @@candumps[id.to_s].push(l.split()[3..-1])}
        end
      end
    end
    {"status" => "success"}  # Response
  end

end
end
end
end
end
