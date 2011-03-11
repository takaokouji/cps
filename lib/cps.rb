require "optparse"
require "pcap"
require "socket"
require "progressbar"

class CPS
  # キャプチャしたパケットを格納したファイルのパス。
  attr_accessor :pcap_path

  # 送信データを表現する。
  SendData = Struct.new(:frame_number, :time, :addr, :data)

  # linux/socket.h
  PF_PACKET = AF_PACKET = 17 
  ETH_P_ALL = [0x3].pack("n").unpack("v").first

  # linux/if_arp.h
  ARPHRD_ETHER = 1

  # /usr/include/linux/if_packet.h
  PACKET_HOST =      0 # To us
  PACKET_BROADCAST = 1 # To all
  PACKET_MULTICAST = 2 # To group
  PACKET_OTHERHOST = 3 # To someone else
  PACKET_OUTGOING =  4 # Outgoing of any type
  PACKET_LOOPBACK =  5 # MC/BRD frame looped back
  PACKET_FASTROUTE = 6 # Fastrouted frame

  # linux/sockios.h
  SIOCGIFINDEX = 0x8933

  SIZEOF_INT = ([0].pack 'I').length

  def initialize
    @pcap_path = nil
    @frame_numbers = []
    @interface = "eth0"
    @dry_run = false
  end

  # 実行する。
  def run
    begin
      open_raw_socket do |socket|
        ifreq = [@interface].pack("a16") + "\0" * 16
        socket.ioctl(SIOCGIFINDEX, ifreq)
        @ifindex = ifreq[16, SIZEOF_INT]
      end
    rescue Errno::EPERM
      puts("Error: you must run as root")
      exit!
    end
    if @frame_numbers.empty?
      send_all_packets = true
    end
    send_data_list = []
    open_pcap(@pcap_path) do |capture|
      first = true
      start_time = 0
      frame_number = 0
      capture.each_packet do |packet|
        frame_number += 1
        if !send_all_packets && !@frame_numbers.include?(frame_number)
          next
        end
        if first
          start_time = packet.time
          first = false
        end
        
        ethrnet_header = packet.raw_data[0, 14]
        
        # struct sockaddr_ll
        addr = ""
        addr << [AF_PACKET].pack("n") # unsigned short  sll_family;
        addr << ethrnet_header[12, 2] # __be16          sll_protocol;
        addr << @ifindex              # int             sll_ifindex;
        addr << [0].pack("n")         # unsigned short  sll_hatype;
        addr << [0].pack("C")         # unsigned char   sll_pkttype;
        addr << [6].pack("C")         # unsigned char   sll_halen;
        addr << ethrnet_header[0, 6] + ([0].pack("C") * 2)   # unsigned char   sll_addr[8];

        send_data_list.push(SendData.new(frame_number, packet.time - start_time, addr, packet.raw_data[14..-1]))
      end
    end

    if send_data_list.empty?
      puts("empty")
      return
    end
    
    print_send_data_list(send_data_list)
    
    open_raw_socket do |socket|
      progress = SendDataProgressBar.new(send_data_list)
      first = true
      prev_time = nil

      send_data_list.each do |send_data|
        if first
          first = false
        else
          sleep(send_data.time - prev_time)
        end
        if !@dry_run
          socket.send(send_data.data, 0, send_data.addr)
        end
        progress.inc
        prev_time = send_data.time
      end
      progress.finish
    end
  end

  # RAWソケットをオープンする。
  def open_raw_socket
    socket = Socket.open(PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
    begin
      yield socket
    ensure
      socket.close
    end
  end

  # コマンドラインオプション(ARGV)を解析する。
  def parse_argv(argv)
    option_parser = OptionParser.new { |opts|
      opts.banner = "Usage: cps [options] <pcap file>"
      opts.separator ""
      opts.separator "Specific options:"
      opts.on("-n", "--frame-number=NO", OptionParser::DecimalInteger, "frame number") do |no|
        @frame_numbers.push(no)
      end
      opts.on("-i", "--interface=NAME", "interface") do |interface|
        @interface = interface
      end
      opts.on("--dry-run", "dry run") do
        @dry_run = true
      end
      opts.on_tail("-h", "--help", "Show this message") do
        puts(opts)
        exit
      end
    }
    option_parser.parse!(argv)
    @pcap_path = argv.shift
    begin
      if !@pcap_path
        raise "too few argument"
      end
      if !File.exist?(@pcap_path)
        raise "file not found: #{@pcap_path}"
      end
    rescue
      puts("Error: #{$!}")
      puts(option_parser)
      exit!
    end
  end

  # パケットキャプチャファイルを開く。
  def open_pcap(path)
    capture = Pcap::Capture.open_offline(path)
    begin
      yield capture
    ensure
      capture.close
    end
  end
  
  # 送信対象のデータを標準出力に出力する。
  def print_send_data_list(send_data_list)
    send_data_list.each do |send_data|
      p([send_data.frame_number, send_data.time, send_data.data.length])
    end
  end
  
  def self.run(argv)
    cps = self.new
    cps.parse_argv(argv)
    cps.run
  end

  class SendDataProgressBar < ProgressBar
    def initialize(send_data_list)
      super("send packets", send_data_list.length)
      @send_data_list = send_data_list
      max_digit = send_data_list.last.frame_number.to_s.length
      @format = "%-#{@title_width}s No.%#{max_digit}d %s %s"
      @format_arguments = [:title, :frame_number, :bar, :stat]
      show
    end

    def fmt_frame_number
      send_data = @send_data_list[@current - 1]
      if send_data
        return send_data.frame_number
      else
        return @send_data_list.last.frame_number
      end
    end
  end
end

class String
  def hexdump
    offset = 0
    result = []

    while raw = self.slice(offset, 16) and raw.length > 0
      # address field
      line = sprintf("%08x  ", offset)
      
      # data field
      for v in raw.unpack('N* a*')
        if v.kind_of? Integer
          line << sprintf("%08x ", v)
        else
          v.each_byte {|c| line << sprintf("%02x", c) }
        end
      end
      
      # text field
      line << ' ' * (47 - line.length)
      line << raw.tr("\000-\037\177-\377", ".")
      
      result << line
      offset += 16
    end
    result
  end
end

