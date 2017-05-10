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
          Reads the identificaion of the VAG Gateway. An open channel is required
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Moritz Lottermann (SySS GmbH)' ],
        'Platform'      => [ 'hardware' ],
        'SessionTypes'  => [ 'hwbridge' ]
    ))

    register_options([
      OptString.new('CANBUS', [true, "CAN Bus to open channel on, defaults to connected bus", nil]),
    ], self.class)

  end

  def run
    kwp = KWP2000.new(client, datastore["CANBUS"], "TP20")
    
  end

end
