##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'VAG TP 2.0 Open Channel Manage',
        'Description'   => %q{
          Opens a communcation channel for Volkswagens TP 2.0 protocol
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Moritz Lottermann (SySS GmbH)' ],
        'Platform'      => [ 'hardware' ],
        'SessionTypes'  => [ 'hwbridge' ]
    ))

    register_options([
      OptString.new('CANBUS', [true, "CAN Bus to open channel on, defaults to connected bus", nil]),
      OptString.new('RECEIVERID', [false, "CAN ID of the messages received by Metasploit", "300"]),
      OptString.new('DIAGPROTO', [false, "Diagnosticprotocol to use for the opened Channel. Default: 0x1 (KWP2000)", 0x1]),
    ], self.class)

    @device_id = nil

  end

  def run
    return if !open_channel
    Thread.new{
      while client.alive?
        keep_alive
        sleep 2
      end
    }
    close_channel    # Makes no sense here? When client is not alive anymore, close channel cannot be sent
  end

  # Opens a TP 2.0 channel by sending a C0 (Channel-Open) request with the wanted ID form SENDERID.
  # The ID of the device will be parsed from the response
  def open_channel
    request_id_high = datastore["RECEIVERID"][0].to_i(16)
    request_id_low = datastore["RECEIVERID"][1..2].to_i(16)

    # TODO: Check 200 and 21F
    response = client.automotive.cansend_and_wait_for_response(datastore["CANBUS"], "200", "21F", [0x1F, 0xC0, 0x00, 0x10, request_id_low, request_id_high, datastore["DIAGPROTO"]], {"MAXPKTS": 1})
    if response["Packets"].size == 0
      print_error("Got no response from device. Could not open channel.")
      return false
    end

    # Parse device-id from response
    @device_id = response["Packets"][0]["DATA"][5][1] + response["Packets"][0]["DATA"][4]
    print_good "Channel is open. Device want's to recieve packages at ID #{@device_id}"
    return true
  end

  # Keeps a TP 2.0 channel alive.
  # Currently using A1 packages, which are settings. TODO: Check for a correct way of keeping alive.
  def keep_alive
    response = client.automotive.cansend_and_wait_for_response(datastore["CANBUS"], @device_id, datastore["SENDERID"], [0xA0, 0x0F, 0x8A, 0xFF, 0x32, 0xFF], {"MAXPKTS": 1})
    if response["Packets"][0]["DATA"] != ["A1", "0F", "8A", "FF", "4A", "FF"]
      print_error("Got invalid response from device. Could not open channel.")
    end
  end

  # Closes a TP 2.0 channel.
  # TODO
  def close_channel
    puts "close"
  end

end
