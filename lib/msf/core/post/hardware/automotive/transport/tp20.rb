# -*- coding: binary -*-
module Msf
class Post
module Hardware
module Automotive
module Transport

require 'msf/core/post/hardware/automotive/cantool'

class TP20
  include Msf::Post::Hardware::Automotive::Cantool

  def initialize(bus, options)
    @bus = bus
    @channel_open = false
    @keep_alive = true

    # Set :TESTERID or 300 if not specified in options.
    @tester_id = (options["TESTERID"] or "300")
    @device_id = nil
    @frame_counter = 0
    @ack_counter = 0
  end

  # Send a raw request. Data can have many bytes. Segmentation will
  # be done automatically.
  # e.g.: data = 'DEADBEEFDEADBEEF'
  def send(data)
    open_channel if !@channel_open

    # Create 2 Byte-length. Add padding of zeros if necessary
    length = (data.size / 2).to_s(16).rjust(4, '0')

    if (data.size / 2) < 6
      # Possible in single frame
      cansend(@bus, @device_id, "1#{@frame_counter.to_s(16)}#{length}#{data}")
      @frame_counter = (@frame_counter + 1 ) % 16
      return
    end

    # Multi-frame message

    # Create first dataframe of 5-byte
    first_data, data = data[0..9],data[10..-1]

    cansend(@bus, @device_id, "2#{@frame_counter.to_s(16)}#{length}#{first_data}")
    @frame_counter = (@frame_counter + 1 ) % 16

    # Loop for the middle frame
    frame_data, data = data[0..13], data[14..-1]   # Get the fist 7 Bytes and keep the rest in Data
    while data != nil
      cansend(@bus, @device_id, "2#{@frame_counter.to_s(16)}#{frame_data}")
      @frame_counter = (@frame_counter + 1 ) % 16
      frame_data, data = data[0..13], data[14..-1]
    end

    # Last Frame
<<<<<<< HEAD
    cansend(@bus, @device_id, "1#{(@frame_counter).to_s(16)}#{frame_data}")
=======
    cansend(@bus, @device_id, "1#{(@frame_counter + 5).to_s(16)}#{frame_data}")
>>>>>>> 6763c89e33da58574edde57b683fde2bc9af68c6
    @frame_counter = (@frame_counter + 1) % 16
  end


  # Sends the given data to the bus and returns the response.
  def send_and_wait_for_response(data)
    send(data)
    sleep 0.1   # Wait for the reception of packages.

    # Get first frame of response
    response = get_next_package
    case response[0][0]
    when "1"
      # Single frame response
      send_ack
      return response[3..-1]
    when "2"
      # Multi frame response
      # Calculate expected number of left packages.
      length = response[1..2].join().to_i(16)
      left_packages = ((length - 5) / 7.0).ceil
      send_ack(left_packages+1)

      result = response[3..7]
      left_packages.times do
        result += get_next_package[1..7]
      end
      return result
    else
      puts "Unknown Package: #{response}"
    end
  end

  # Returns the next package from the buffer.
  # If it is a response of A3 (Keep Alive), the packet will be ignored
  def get_next_package
    # Check if packet is an ACK. -> Ignore for now
    def ack?(packet)
      if packet.size == 1 && packet[0][0] == 'B'
        return true
      end
      return false
    end
      # Check if packet is a response of keep_alive -> Ignore
    def keep_alive?(packet)
      if packet.size == 6 && packet == ["A1", "0F", "8A", "FF", "4A", "FF"]
        return true
      end
      return false
    end

    p = nil
    loop do
      p = get_buffered_packages(@tester_id, 1)[0]
      break if !ack?(p) && !keep_alive?(p)
    end

    return p
  end

  # Opens a TP 2.0 channel by sending a C0 (Channel-Open) request with the wanted ID form RECEIVERID.
  # The ID of the device will be parsed from the response
  def open_channel
    # TODO: Check 200 and 21F
    candump_listener(@bus, "21F")
    cansend(@bus, "200", "1FC00010#{@tester_id[1..2]}0#{@tester_id[0]}01")
    sleep 0.05
    response = get_buffered_packages("21F", 1)
    if response.size == 0
      puts "Got no response from device. Could not open channel."
      return false
    end

    # TODO Check for correctness of response

    # Parse device-id from response
    @device_id = response[0][5][1] + response[0][4]
    puts "Channel is open. Device want's to recieve packages at ID #{@device_id}"
    @channel_open = true

    # Send Channel Parameters
    candump_listener(@bus, @tester_id)
    cansend(@bus, @device_id, "A00F8AFF32FF")
    sleep 0.1
    response = get_buffered_packages(@tester_id, 1)
    if response[0] != ["A1", "0F", "8A", "FF", "4A", "FF"]
      puts("Got invalid response from device. Could not open channel.")
    end

    keep_alive
    sleep 0.5 # To prevent timing issues. "send" could be faster than the first keep_alive
    return true
  end

  # Closes the current open channel
  def stop_communication
    @keep_alive = false
    cansend(@bus, @device_id, 'A8')
  end

  # Send an acknowledge.
  # packets is the number of packets received.
  # An acknowledge is 1 Byte: "B<pkg_counter>"
  def send_ack(packets=1)
    @ack_counter = (@ack_counter + packets) % 16
    cansend(@bus, @device_id, "B#{@ack_counter.to_s(16)}")
  end

  # Keeps a TP 2.0 channel alive.
  # Currently using A1 packages, which are settings. TODO: Check for a correct way of keeping alive.
  def keep_alive
    Thread.new do
      while @keep_alive
        cansend(@bus, @device_id, "A3")
        sleep 0.01
        response = get_buffered_packages(@tester_id, 1)
        if response[0] != ["A1", "0F", "8A", "FF", "4A", "FF"]
          puts("Got invalid response from device. Channel is probably not alive anymore")
        end
        sleep 0.5
      end
    end
    sleep 0.5   # Wait for the Keep-alive to be sent the first time
  end

  def stop_keep_alive()
    @keep_alive = false
  end

end

end
end
end
end
end
