##
#
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# TODO: SSL Support, Authentication, Listen to localhost only by default
#
##

require 'msf/core'
require 'msf/core/post/hardware/automotive/transport/tp20'
require 'msf/core/post/hardware/automotive/cantool'

class MetasploitModule < Msf::Auxiliary

  include Msf::Post::Hardware::Automotive::Transport
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report
  include Msf::Post::Hardware::Automotive::Cantool

  HWBRIDGE_API_VERSION = "0.0.1"

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Carbridge Server',
      'Description' => %q{
          This module sets up a web server to bridge communications between
        Metasploit and physically attached CAN hardware.
        This brdige allows to send and recieve raw CAN messages.
      },
      'Author'      => [ 'Moritz Lottermann (SySS GmbH)' ],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'WebServer' ]
        ],
      'PassiveActions' =>
        [
          'WebServer'
        ],
      'DefaultAction'  => 'WebServer'))

    @operational_status = 0   # 0=unk, 1=connected, 2=not connected
    @last_errors = {}
    @server_started = Time.new
    @can_interfaces = []

    @transport_protocol = nil

  end

  def set_transport_protocol(bus, protocol, options)
    return if "Msf::Post::Hardware::Automotive::Transport::#{protocol}" == @transport_protocol.class.to_s

    if @transport_protocol != nil && @transport_protocol.class != protocol
      print_warning("WARNING: Changing transport protocol from #{@transport_protocol} to #{protocol}")
    end

    case protocol
    when "TP20"
      @transport_protocol = TP20.new(bus, options)
    else
      print_error "Unknown protocol: #{protocol}"
    end
  end

  # Detects CAN interfaces based on their name.
  def detect_can
    @can_interfaces = []
    Socket.getifaddrs.each do |i|
      if i.name =~ /^can\d+$/ || i.name =~ /^vcan\d+$/ || i.name =~ /^slcan\d+$/
        @can_interfaces << i.name
      end
    end
  end

  def get_status
    status = {}
    status["operational"] = @operational_status
    status["hw_specialty"] = {}
    status["hw_capabilities"] = {}
    status["last_10_errors"] = @last_errors # NOTE: no support for this yet
    status["api_version"] = HWBRIDGE_API_VERSION
    status["fw_version"] = "not supported"
    status["hw_version"] = "not supported"
    unless @can_interfaces.empty?
      status["hw_specialty"]["automotive"] = true
      status["hw_capabilities"]["can"] = true
    end
    status["hw_capabilities"]["custom_methods"] = true # To test custom methods
    status
  end

  def get_statistics
    stats = {}
    stats["uptime"] = Time.now - @server_started
    stats["packet_stats"] = "not supported"
    stats["last_request"] = "not supported"
    stats["voltage"] = "not supported"
    stats
  end

  def get_datetime
    { "system_datetime" => Time.now }
  end

  def get_timezone
    { "system_timezone" => Time.now.getlocal.zone }
  end

  def get_ip_config
  end

  def get_auto_supported_buses
    detect_can()
    buses = []
    @can_interfaces.each do |can|
      buses << { "bus_name" => can }
    end
    buses
  end

  # Converts candump output to {Packets => [{ ID=> id DATA => [] }]}
  def candump2hash(str_packets)
    hash = {}
    hash["Packets"] = []
    lines = str_packets.split(/\n/)
    lines.each do |line|
      if line =~ /\w+\s+(\w+)   \[\d\]  (.+)$/
        id = $1
        str_data = $2
        data = str_data.split
        hash["Packets"] << { "ID" => id, "DATA" => data }
      end
    end
    hash
  end


  def not_supported
    { "status" => "not supported" }
  end

  def on_request_uri(cli, request)
    if request.uri =~ /status$/i
      print_status("Sending status...")
      send_response_html(cli, get_status().to_json(), { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /statistics$/i
      print_status("Sending statistics...")
      send_response_html(cli, get_statistics().to_json(), { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /settings\/datetime\/get$/i
      print_status("Sending Datetime")
      send_response_html(cli, get_datetime().to_json(), { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /settings\/timezone\/get$/i
      print_status("Sending Timezone")
      send_response_html(cli, get_timezone().to_json(), { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /custom_methods$/i
      print_status("Sending custom methods")
      send_response_html(cli, get_custom_methods().to_json(), { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /custom\/sample_cmd\?data=(\S+)$/
      print_status("Request for custom command with args #{$1}")
      send_response_html(cli, sample_custom_method($1).to_json(), { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /automotive/i
      if request.uri =~ /automotive\/supported_buses/
        print_status("Sending known buses...")
        send_response_html(cli, get_auto_supported_buses().to_json, { 'Content-Type' => 'application/json' })
      elsif request.uri =~ /automotive\/(\w+)\/setTransportProtocol\?tp=(\w+)&options=(.+)/
        print_status("Setting transport protocol to #{$2}")
        options = JSON.parse(URI.unescape($3))
        set_transport_protocol($1, $2, options)
      elsif request.uri =~ /automotive\/(\w+)\/sendData\?data=(\w+)/
        @transport_protocol.send($2)
      elsif request.uri =~ /automotive\/(\w+)\/cansend\?id=(\w+)&data=(\w+)/
        cansend($1, $2, $3)
      elsif request.uri =~ /automotive\/(\w+)\/sendDataAndWaitForResponse\?data=(\w+)/
        send_response_html(cli, @transport_protocol.send_and_wait_for_response($2).to_json, {'Content-Type' => 'application/json' })
      else
        send_response_html(cli, not_supported().to_json(), { 'Content-Type' => 'application/json' })
      end
    else
      send_response_html(cli, not_supported().to_json(), { 'Content-Type' => 'application/json' })
    end
  end

  def run
    detect_can
    @server_started = Time.now
    exploit
  end

end
