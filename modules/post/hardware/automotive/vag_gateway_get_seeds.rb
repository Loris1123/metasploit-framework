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
          Retrieves securityaccess seeds from the ECU. Can be used for analyzes
          Writes the result into FILE"
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Moritz Lottermann (SySS GmbH)' ],
        'Platform'      => [ 'hardware' ],
        'SessionTypes'  => [ 'hwbridge' ]
    ))

    register_options([
      OptString.new('CANBUS', [true, "CAN Bus to open channel on, defaults to connected bus", nil]),
      OptInt.new('TIMES', [true, "The number of seeds that shall bee retrieved", nil]),
      OptString.new('FILE', [true, "The file to write the results to", nil])
    ], self.class)

  end

  def run
    kwp = KWP2000.new(client, datastore["CANBUS"], "TP20")
    seeds = []

    datastore["TIMES"].times do
      response = kwp.security_access_request_seed("03")
      seeds.push(response) if response != nil
      sleep 0.1
    end

    file = File.open(datastore["FILE"], 'w')
    seeds.each do |seed|
      file.write("#{seed}\n")
    end
    file.close
  end

end
