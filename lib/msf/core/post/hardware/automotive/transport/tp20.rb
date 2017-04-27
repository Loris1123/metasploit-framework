# -*- coding: binary -*-
module Msf
class Post
module Hardware
module Automotive
module Transport

class TP20

  @channel_open = false
  @ack_counter = 0
  @pkg_counter = 1

  def initialize(client, canbus, sender_id="300")
    @client = client
    @canbus = canbus
    @sender_id = sender_id
    @device_id = nil # Will be set by open_channel
  end


  def send(data)
    open_channel if !@channel_open
    puts "Channel is open. now send"
    @client.automotive.cansend(@canbus, @device_id, data)
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
