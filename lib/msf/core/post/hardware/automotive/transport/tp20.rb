# -*- coding: binary -*-
module Msf
class Post
module Hardware
module Automotive
module Transport

class TP20

  def initialize(client, canbus, sender_id="300")
    @client = client
    @canbus = canbus
    @sender_id = sender_id
    @device_id = nil # Will be set by open_channel
    @frame_counter = 1
    @channel_open = false
    @ack_counter = 0
  end


  def send(data)
    open_channel if !@channel_open
    puts "Channel is open. now send"

    # Create 2 Byte-length. Add padding of zeros if necessary
    length = (data.size / 2).to_s(16).rjust(4, '0')

    if (data.size / 2) < 6
      # Possible in single frame
      puts "1#{@frame_counter.to_s(16)}#{length}#{data}"
      @frame_counter = (@frame_counter + 1 ) % 16
      return
    end

    # Multi-frame message

    # Create first data of 5-byte
    first_data, data = data[0..9],data[10..-1]
    puts "2#{@frame_counter.to_s(16)}#{length}#{first_data}"
    @frame_counter = (@frame_counter + 1 ) % 16

    # Loop for the middle frame
    frame_data, data = data[0..13], data[14..-1]
    while data != nil
      puts "2#{@frame_counter.to_s(16)}#{frame_data}"
      @frame_counter = (@frame_counter + 1 ) % 16
      frame_data, data = data[0..13], data[14..-1]
    end

    # Last Frame
    puts "1#{@frame_counter.to_s(16)}#{frame_data}"
    @frame_counter = (@frame_counter + 1 ) % 16
  end

  # Opens a TP 2.0 channel by sending a C0 (Channel-Open) request with the wanted ID form RECEIVERID.
  # The ID of the device will be parsed from the response
  def open_channel
    request_id_high = @sender_id[0].to_i(16)
    request_id_low = @sender_id[1..2].to_i(16)

    # TODO: Check 200 and 21F
    response = @client.automotive.cansend_and_wait_for_response(@canbus, "200", "21F", [0x1F, 0xC0, 0x00, 0x10, request_id_low, request_id_high, 0x01], {"MAXPKTS": 1})
    if response["Packets"].size == 0
      puts "Got no response from device. Could not open channel."
      return false
    end

    # TODO Check for correctness of response

    # Parse device-id from response
    @device_id = response["Packets"][0]["DATA"][5][1] + response["Packets"][0]["DATA"][4]
    puts "Channel is open. Device want's to recieve packages at ID #{@device_id}"
    @channel_open = true

    keep_alive
    sleep 0.5 # To prevent timing issues. "send" could be faster than the first keep_alive
    return true
  end

  # Keeps a TP 2.0 channel alive.
  # Currently using A1 packages, which are settings. TODO: Check for a correct way of keeping alive.
  def keep_alive
    Thread.new do
      while @client.alive?
        response = @client.automotive.cansend_and_wait_for_response(@canbus, @device_id, @sender_id, [0xA0, 0x0F, 0x8A, 0xFF, 0x32, 0xFF], {"MAXPKTS": 1})
        puts "Response: #{response}"
        if response["Packets"][0]["DATA"] != ["A1", "0F", "8A", "FF", "4A", "FF"]
          puts("Got invalid response from device. Could not open channel.")
        end
        sleep 1.5
      end
    end
  end

end

end
end
end
end
end
