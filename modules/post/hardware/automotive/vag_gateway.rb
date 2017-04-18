##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/post/hardware/automotive/kwp2000'

class MetasploitModule < Msf::Post

  include Msf::Post::Hardware::Automotive::KWP2000

  # parameter IDs (PIDs) for Saab Trionic 7
  VEHICLE_IDENTIFICATION_NUMBER = 0x90
  IMMOBILIZER_ID = 0x91
  SOFTWARE_PART_NUMBER = 0x94
  SOFTWARE_VERSION = 0x95
  ENGINE_TYPE = 0x97
  SYMBOL_TABLE_OFFSET = 0x9B


  def initialize(info={})
    super( update_info( info,
                       'Name'          => 'Module for a Volkswagen (VAG) Gateway',
                       'Description'   => %q{ Post Module to query information via
                       keyword protocol 2000 (KWP2000) over CAN},
                               'License'       => MSF_LICENSE,
                               'Author'        => ['Moritz Lottermann (SySS GmbH)'],
                               'Platform'      => ['hardware'],
                               'SessionTypes'  => ['hwbridge']
                      ))
    register_options([
      OptInt.new('SRCID', [true, "Module ID to query", 0x220]),
      OptInt.new('DSTID', [false, "Expected reponse ID, defaults to SRCID + 0x18", 0x238]),
      OptString.new('CANBUS', [false, "CAN Bus to perform scan on, defaults to connected bus", nil])
    ], self.class)

  end

  def run
    print_status("Running")

    data = [0x1f, 0xc0, 0x00, 0x10, 0x00, 0x03, 0x01]
    puts client.automotive.cansend_and_wait_for_response("slcan0", "200", "21F", data, {"MAXPKTS": 1})

  end
end
