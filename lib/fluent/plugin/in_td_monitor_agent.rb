module Fluent
  require_relative 'tdms_ext_fluentd'
  require_relative 'out_td_counter'

  class TDMonitorAgentInput < Input
    VERSION = "0.2.1"

    Plugin.register_input('td_monitor_agent', self)

    config_param :apikey, :string, :secret => true
    config_param :emit_interval, :time, :default => 60
    config_param :endpoint, :string, :default => 'https://api.treasuredata.com:443'
    config_param :http_proxy, :string, :default => nil
    config_param :instance_id, :string, :default => nil
    config_param :retry_limit, :integer, :default => 5
    config_param :connect_timeout, :integer, :default => 10
    config_param :read_timeout, :integer, :default => 10
    config_param :send_timeout, :integer, :default => 10

    config_param :disable_node_info, :bool, :default => true

    unless method_defined?(:log)
      define_method(:log) { $log }
    end

    def initialize
      super
      require 'json'
      require 'ohai'
      require 'httpclient'
    end

    class TimerWatcher < Coolio::TimerWatcher
      def initialize(interval, repeat, log, &callback)
        @callback = callback
        # Avoid long shutdown time
        @num_call = 0
        @call_interval = interval / 10
        @log = log
        super(10, repeat)
      end

      def on_timer
        @num_call += 1
        if @num_call >= @call_interval
          @num_call = 0
          @callback.call
        end
      rescue => e
        @log.error e.to_s
        @log.error_backtrace
      end
    end

    def configure(conf)
      super

      @agent_id = get_agent_id
      @mac_address = Mac.address
      @ca_file = find_ca_file
      $log.warn "crt file not found. Use VERIFY_NONE in SSL context" if @ca_file.nil?
      $log.warn "Fluentd Monitoring Service will be shutdown. Remove td_monitor_agent section from configuration"
    end

    def start
      Engine.set_tag_path

      @started_at = Time.now.to_i
      @monitor_agent = ExMonitorAgentInput.new
      begin
        unless @disable_node_info
          @cpu_stat = CpuStat.new
          @disk_stat = DiskStat.new(FileBuffer.class_variable_get(:@@buffer_paths).keys)
          @memory_stat = MemoryStat.new
          @bandwidth_stat = BandwidthStat.new(@emit_interval)
        end
      rescue => e
        @disable_node_info = true
        log.warn "Failed to get system metrics. Set 'disable_node_info' to true: #{e}"
      end
      @counters = collect_counters

      unless register_instance_info
        log.warn "Can't register instance information at start"
      end

      @loop = Coolio::Loop.new
      @timer = TimerWatcher.new(@emit_interval, true, log, &method(:on_timer))
      @loop.attach(@timer)
      @thread = Thread.new(&method(:run))
    end

    def shutdown
      log.info "shutdown td_monitor_agent plugin"

      @loop.watchers.each {|w| w.detach }
      @loop.stop
      @thread.join
    end

    def run
      @loop.run
    rescue => e
      log.error "unexpected error", :error=> e.to_s
      log.error_backtrace
    end

    EVENT_ENDPOINT_PATH = '/v1/monitoring/start'

    def on_timer
      retrying = false
      @retry_limit.times { |i|
        if send_to_tdms(EVENT_ENDPOINT_PATH, collect_info)
          if retrying
            log.warn "retry succeeded after #{i} retry"
          end
          return
        else
          retrying = true
        end
        sleep 2
      }
      log.error "Send instance metrics failed. Try next #{@emit_interval} seconds"
    end

    private

    def find_ca_file
      ca_file = File.join(File.dirname(__FILE__), '..', '..', '..', 'data', 'ca-bundle.crt')
      begin
        File.read(ca_file)
        return File.expand_path(ca_file)
      rescue Errno::ENOENT => e
      end

      ca_file = File.join(File.dirname(__FILE__), 'ca-bundle.crt')
      begin
        File.read(ca_file)
        return File.expand_path(ca_file)
      rescue Errno::ENOENT => e
      end

      nil
    end

    BASIC_INFO_PLUGINS = %W(os platform hostname)

    def register_instance_info
      info = basic_info.dup
      info.merge!(collect_info)

      send_to_tdms(EVENT_ENDPOINT_PATH, info)
    end

    def basic_info
      if @basic_info.nil?
        ohai = Ohai::System.new
        BASIC_INFO_PLUGINS.each { |plugin|
          ohai.require_plugin(plugin)
        }
        @basic_info = {'info' => {'os' => ohai[:platform], 'os_version' => ohai[:platform_version], 'hostname' => ohai[:fqdn]}}
      end
      @basic_info
    end

    def collect_info
      info = {}
      info['plugins'] = collect_fluentd_info
      info['node_data'] = collect_node_info unless @disable_node_info
      info['traffic'] = collect_traffic_info unless @counters.empty?
      info.merge!(basic_info)
      info
    end

    def collect_node_info
      result = {}
      result['cpu'] = @cpu_stat.stats
      result['disk'] = @disk_stat.stats
      result['memory'] = @memory_stat.stats
      result['bandwidth'] = @bandwidth_stat.stats
      result
    end

    def collect_fluentd_info
      result = {}
      @monitor_agent.plugins_info_all.map { |plugin|
        id = plugin.delete('plugin_id')
        result[id] = plugin
      }
      result
    end

    def collect_traffic_info
      tagged_counts = {}
      @counters.map { |counter| counter.flush_counts }.each { |counts|
        counts.each { |tag, count|
          if c = tagged_counts[tag]
            c[Fluent::TDCounterOutput::BYTES_FIELD] += count[Fluent::TDCounterOutput::BYTES_FIELD]
            c[Fluent::TDCounterOutput::COUNT_FIELD] += count[Fluent::TDCounterOutput::COUNT_FIELD]
          else
            tagged_counts[tag] = count
          end
        }
      }
      tagged_counts
    end

    def send_to_tdms(path, info)
      #puts JSON.pretty_generate('agent_id' => @agent_id, 'data' => info, 'time' => Time.now.to_i); return true
      begin
        res = post(path, info)
        unless res.code.to_s.start_with?('2')
          log.warn "Get an error response: code = #{res.code}, message = #{res.body}"
          return false
        end
      rescue => e
        log.warn "Failed to send metrics: error = #{e.to_s}"
        return false
      end
      true
    end

    def get_agent_id
      id = @instance_id
      if id.nil?
        ObjectSpace.each_object(Fluent::Supervisor) { |obj|
          # TODO: Improve getting id using instance-id or something
          id = obj.instance_variable_get(:@config_path)
        }
      end
      id
    end

    def collect_counters
      counters = []
      ObjectSpace.each_object(Fluent::TDCounterOutput) { |obj|
        counters << obj 
      }
      counters
    end

    def post(path, params = nil)
      client, header = new_client
      header['Content-Type'] = 'application/json'

      target = build_endpoint(path)
      body = {'mac_addr' => @mac_address, 'agent_id' => @agent_id, 'started_at' => @started_at,
        'time' => Time.now.to_i, 'version' => VERSION, 'data' => params.to_json}.to_json
      # TODO: Use post_content supports redirect
      client.post(target, body, header)
    end

    def build_endpoint(path)
      "#{@endpoint}/#{path}"
    end

    def new_client(opts = {})
      client = HTTPClient.new(@http_proxy, "TDMS Agent #{VERSION}")
      client.connect_timeout = @connect_timeout
      client.receive_timeout = @read_timeout
      client.send_timeout = @send_timeout

      if ssl?
        if @ca_file
          client.ssl_config.add_trust_ca(@ca_file)
          client.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_PEER
        else
          client.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end
      end

      header = {}
      if @apikey
        header['Authorization'] = "TD1 #{@apikey}"
      end
      header['Date'] = Time.now.rfc2822

      return client, header
    end

    def ssl?
      uri = URI.parse(@endpoint)
      uri.scheme == 'https'
    end

    def e(s)
      require 'cgi'
      CGI.escape(s.to_s)
    end

    # TODO: Get fluentd's process usage of CPU and Memory

    class CpuStat
      def initialize
        @stats = cpu_stats
      end

      CPU_KEYS = %W(user nice system idle iowait irq sirq)
      USE_CPU_KEYS = [0, 2]

      def stats
        res = {}

        stats = cpu_stats
        diff  = @stats.map.with_index { |stat, i| stats[i] - stat }
        total = diff.inject(0) { |sum, n| sum + n }
        total = 1 if total.zero?

        diff.each_with_index { |stat, i|
          if USE_CPU_KEYS.include?(i)
            res[CPU_KEYS[i]] = stat.to_f / total * 100
          end
        }
        @stats = stats
        res['loadavg1'] = loadavg_stats

        res
      end

      private

      def cpu_stats
        File.open("/proc/stat") { |f|
          stats = f.gets.split(' ', CPU_KEYS.size + 1)
          return stats.map { |stat| stat.to_i }
        }
      end

      def loadavg_stats
        File.open("/proc/loadavg") { |f|
          stats = f.gets.split(' ', 2)
          return stats.first.to_f
        }
      end
    end

    class DiskStat
      def initialize(paths)
        mounts = mount_points
        @targets = paths.map { |path| select_mount(path, mounts) }.sort.uniq
      end

      def stats
        res = {}
        `df -B G -P`.each_line.with_index { |line, i|
          if i.nonzero?
            columns = line.strip.split(' ')
            mount = columns[-1].strip
            if @targets.include?(mount)
              usage = columns[-2].chop.to_i
              res[mount] = usage
            end
          end
        }
        res
      end

      private

      def select_mount(path, mounts)
        mount = mounts.first
        mounts[1..-1].each { |m|
          if path.start_with?(m) && (m.length > mount.length)
            mount = m
          end
        }
        mount
      end

      def mount_points
        `df -B G -P`.each_line.map.with_index { |line, i|
          if i.zero?
            nil
          else
            columns = line.strip.split(' ')
            columns[-1].strip
          end
        }.compact
      end
    end

    class MemoryStat
      def stats
        res = {}
        `free -o`.each_line.with_index { |line, i|
          case
          when line.start_with?('Mem:')
            columns = line.strip.split(' ')
            total = columns[1].to_i
            free = columns[3].to_i + columns[5].to_i + columns[6].to_i
            res['usage'] = ((total - free).to_f / total * 100).to_i
          #when line.start_with?('Swap:')
          #  columns = line.strip.split(' ')
          #  res['swap'] = (columns[2].to_f / columns[1].to_i * 100).to_i
          end
        }
        res
      end
    end

    # bandwidth used ratio in bytes/s
    class BandwidthStat
      def initialize(interval)
        @interval = interval
        @bytes_cache = current_total_bytes
      end

      def stats
        res = {}
        last_bytes, @bytes_cache = @bytes_cache, current_total_bytes
        res['ratio'] = (@bytes_cache - last_bytes) / @interval
        res
      end

      def current_total_bytes
        network_bytes = `grep eth0: /proc/net/dev`.lstrip[5..-1].strip.split(/\s+/)
        received_bytes = network_bytes[0].to_i
        transmitted_bytes = network_bytes[8].to_i
        received_bytes + transmitted_bytes
      rescue => e
        0
      end
    end

    # from macaddr gem
    module Mac
      class << self

        ##
        # Accessor for the system's first MAC address, requires a call to #address
        # first

        attr_accessor "mac_address"

        ##
        # Discovers and returns the system's MAC addresses.  Returns the first
        # MAC address, and includes an accessor #list for the remaining addresses:
        #
        #   Mac.addr # => first address
        #   Mac.addr.list # => all addresses

        def address
          return @mac_address if defined? @mac_address and @mac_address
          re = %r/[^:\-](?:[0-9A-F][0-9A-F][:\-]){5}[0-9A-F][0-9A-F][^:\-]/io
          cmds = '/sbin/ifconfig', '/bin/ifconfig', 'ifconfig', 'ipconfig /all', 'cat /sys/class/net/*/address'

          null = test(?e, '/dev/null') ? '/dev/null' : 'NUL'

          output = nil
          cmds.each do |cmd|
            begin
              r, w = IO.pipe
              ::Process.waitpid(spawn(cmd, :out => w))
              w.close
              stdout = r.read
              next unless stdout and stdout.size > 0
              output = stdout and break
            rescue
              # go to next command!
            end
          end
          raise "all of #{ cmds.join ' ' } failed" unless output

          @mac_address = parse(output)
        end

        def parse(output)
          lines = output.split(/\n/)

          candidates = lines.select{|line| line =~ RE}
          raise 'no mac address candidates' unless candidates.first
          candidates.map!{|c| c[RE].strip}

          maddr = candidates.first
          raise 'no mac address found' unless maddr

          maddr.strip!
          maddr.instance_eval{ @list = candidates; def list() @list end }
          maddr
        end
      end

      RE = %r/(?:[^:\-]|\A)(?:[0-9A-F][0-9A-F][:\-]){5}[0-9A-F][0-9A-F](?:[^:\-]|\Z)/io
    end
  end
end
