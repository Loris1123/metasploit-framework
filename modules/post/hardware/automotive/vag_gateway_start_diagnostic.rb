##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/hardware/automotive/application/kwp2000'

class MetasploitModule < Msf::Post

  include Msf::Post::Hardware::Automotive::Application

  def initialize(info={})

    super(update_info(info,
        'Name'          => 'VW TP 2.0 Rend Request',
        'Description'   => %q{
          Starts a diagnostic session for a VAG Gateway.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Moritz Lottermann (SySS GmbH)' ],
        'Platform'      => [ 'hardware' ],
        'SessionTypes'  => [ 'hwbridge' ]
    ))

    register_options([
      OptString.new('CANBUS', [true, "CAN Bus to open channel on, defaults to connected bus", nil]),
      OptString.new('TESTERID', [false, "ID of the messages directed to metaspliot", nil]),
    ], self.class)

  end

  def run
    kwp = KWP2000.new(client, datastore["CANBUS"], "TP20", {TESTERID: datastore["TESTERID"]})
    response = kwp.start_diagnostic_session("89")
    if response == "89"
      print_good("Started diagnostc session successfully")
    else
      print_error("Could not start diagnostic session")
    end

  end

end
