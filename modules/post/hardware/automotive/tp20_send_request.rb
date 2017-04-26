##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'VW TP 2.0 Rend Request',
        'Description'   => %q{
          Sends a TP VW TP 2.0 Request on the given CAN bus and returns the response.
          Precondition is an open TP 2.0 channel. Which can be opened by running post/hardware/automotive/tp20_open_channel
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Moritz Lottermann (SySS GmbH)' ],
        'Platform'      => [ 'hardware' ],
        'SessionTypes'  => [ 'hwbridge' ]
    ))

    register_options([
      OptString.new('CANBUS', [true, "CAN Bus to open channel on, defaults to connected bus", nil]),
      OptString.new('SENDERID', [false, "CAN ID of the messages sent by Metasploit", "32E"]),
      OptString.new('RECEIVERID', [false, "CAN ID of the messages sent by the Device", "300"]),
    ], self.class)

  end

  def run
    response = client.automotive.cansend_and_wait_for_response(datastore["CANBUS"], datastore["SENDERID"], datastore["RECEIVERID"], [0x10, 0x00, 0x02, 0x10, 0x89], {"MAXPKTS": 1})
    puts response
  end

  # acknowledges the reception of a number of packets.
  def send_ack(packets=1)
  end
end
