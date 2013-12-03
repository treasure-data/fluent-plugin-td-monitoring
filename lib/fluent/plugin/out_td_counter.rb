module Fluent
  class TDCounterOutput < Output
    Plugin.register_output('td_counter', self)

    #config_param :aggregate, :string, :default => 'tag'
    #config_param :exact_count, :bool, :default => true

    attr_accessor :counts
    attr_reader :output

    def initialize
      super
      @output = nil
    end

    def configure(conf)
      super

      conf.elements.select { |e|
        e.name == 'store'
      }.each { |e|
        type = e['type']
        unless type
          raise ConfigError, "Missing 'type' parameter on <store> directive"
        end
        $log.debug "adding store type = #{type.dump}"

        @output = Plugin.new_output(type)
        @output.configure(e)
      }

      @counts = {}
      @mutex = Mutex.new
    end

    def start
      super

      unless check_td_monitor_agent
        $log.warn "in_td_monitor_agent not found. If you want to use out_td_counter, then you should configure in_td_monitor_agent in same configuration"
      end

      unless @output.nil?
        @output.start
      end
    end

    def shutdown
      unless @output.nil?
        @output.shutdown
      end

      super
    end

    COUNT_FIELD = 'count'
    BYTES_FIELD = 'bytes'

    def count_initialized
      {COUNT_FIELD => 0, BYTES_FIELD => 0}
    end

    def countup(tag, counts, bytes)
      @mutex.synchronize {
        @counts[tag] ||= count_initialized
        count = @counts[tag]
        count[COUNT_FIELD] += counts
        count[BYTES_FIELD] += bytes
      }
    end

    def flush_counts
      counts = nil
      @mutex.synchronize {
        counts = @counts
        @counts = {}
      }
      counts
    end

    def emit(tag, es, chain)
      count = 0
      bytes = 0

      # TODO: if bytes is not needed, use Event#num_records to reduce processing time
      es.each { |time, record|
        count += 1
        bytes += record.to_msgpack.bytesize
      }

      countup(tag, count, bytes)
      unless @output.nil?
        @output.emit(tag, es, chain)
      end

      chain.next
    end

    private

    def check_td_monitor_agent
      found = false
      ObjectSpace.each_object(Fluent::TDMonitorAgentInput) { |obj|
        found = true
      }
      found
    end
  end
end
