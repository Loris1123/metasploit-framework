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


    @ack_counter = 0

  end

  #
  # Send a request to the gateway and expect a given response.
  # Returns true of response was as expected. False otherwise.
  # Example:
  # send_request_and_expect("123", [0xDE, 0xAD], "321", [0xBE, 0xEF])
  def send_request_and_expect(request_id, request, expected_id, expected)
    response = client.automotive.cansend_and_wait_for_response(datastore["CANBUS"], "#{request_id}", "#{expected_id}", request, {"MAXPKTS": 1})
    if response["Packets"].size == 0
      raise("Gateway did not response or answered with a wrong ID")
    end
    if response["Packets"][0]["DATA"].size == expected.size
      # response format is ["DE", "AD"]
      # Change to [0xDE, 0xAD]
      response["Packets"][0]["DATA"].map!{|byte| byte.to_i(16)}

      if response["Packets"][0]["DATA"] == expected
        return true
      end
    end

    raise("Gateway did not response correctly")
  end

  def run
    print_status("Running")

    init_communication()

  end


  def init_communication
    send_request_and_expect("200", [0x1F, 0xC0, 0x00, 0x10, 0x00, 0x03, 0x01], "21F", [0x00, 0xD0, 0x00, 0x03, 0x2E, 0x03, 0x01])
    send_request_and_expect("32E", [0xA0, 0x0F, 0x8A, 0xFF, 0x32, 0xFF], "300", [0xA1, 0x0F, 0x8A, 0xFF, 0x4A, 0xFF])

    # Expecting multiple packages
    client.automotive.cansend_and_wait_for_response(datastore["CANBUS"], "32E", "300", [0x10, 0x00, 0x02, 0x10, 0x89], {"MAXPKTS": 2})
    send_ack
    client.automotive.cansend_and_wait_for_response(datastore["CANBUS"], "32E", "300", [0x11, 0x00, 0x02, 0x1A, 0x9B], {"MAXPKTS": 2})
    send_ack
    client.automotive.cansend(datastore["CANBUS"], "32E", "22000722F187F189")
    client.automotive.cansend_and_wait_for_response(datastore["CANBUS"], "32E", "300", [0x13, 0xF1, 0x97], {"MAXPKTS": 7})
    send_ack(6)
  end

  # Sending an ACK to the sender.
  # ack_counter will be incremented by the number of packets recieved.
  # Counter is only 4 Bits long. The Byte B<ACK_COUNTER> will be sent.
  def send_ack(recieved_packets=1)
    @ack_counter = (@ack_counter + recieved_packets) % 16
    client.automotive.cansend(datastore["CANBUS"], "32E", "B#{@ack_counter.to_s(16)}")
  end


end
