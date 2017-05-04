##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/hardware/automotive/transport/tp20'
require 'msf/core/post/hardware/automotive/application/kwp2000'


class MetasploitModule < Msf::Post

  include Msf::Post::Hardware::Automotive::Transport
  include Msf::Post::Hardware::Automotive::Application

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
    tp = TP20.new(client, datastore["CANBUS"])
    kwp = KWP2000.new(tp)
    response = kwp.start_diagnostic_session("89")
    if response == "89"
      print_good("Started diagnostc session successfully")
    else
      print_error("Could not start diagnostic session")
    end
  end

end
