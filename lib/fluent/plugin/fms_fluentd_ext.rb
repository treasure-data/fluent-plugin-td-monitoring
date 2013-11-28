module Fluent
  require 'fluent/plugin/in_monitor_agent'

  class MonitorAgentInput
    def self.collect_children(pe, array=[])
      array << pe
      if pe.is_a?(MultiOutput) && pe.respond_to?(:outputs)
        pe.outputs.each {|nop|
          collect_children(nop, array)
        }
      elsif pe.respond_to?(:output) && pe.output.is_a?(Output)
        collect_children(pe.output, array)
      end
      array
    end
  end

  class ExMonitorAgentInput < MonitorAgentInput
    TD_MONITOR_INFO = MONITOR_INFO.merge(
      'buffer_type' => 'buffer_type',
      'buffer_path' => '@buffer.buffer_path',
      'flush_interval' => '@flush_interval')
    %W(plugin_id config buffer_queue_length buffer_total_queued_size retry_count).each { |k|
      TD_MONITOR_INFO.delete(k)
    }

    TD_PLUGIN_METRIC_INFO = { 
      'buffer_queue_length' => '@buffer.queue_size',
      'buffer_queued_size' => '@buffer.total_queued_chunk_size',
      'emit_count' => '@emit_count',
      'retry_count' => '@error_history.size'
    }

    def get_monitor_info(pe, opts = {})
      obj = {'plugin_id' => pe.id_or_tag_path}

      conf = {}
      TD_MONITOR_INFO.each_pair { |key, code|
        begin
          v = pe.instance_eval(code)
          unless v.nil?
            conf[key] = v
          end
        rescue
        end
      }
      obj['config'] = conf

      if conf['output_plugin'] && conf.has_key?('buffer_type')
        obj['metrics'] = get_plugin_metric(pe)
      end

      obj
    end

    def get_plugin_metric(pe)
      metrics = {}
      TD_PLUGIN_METRIC_INFO.each_pair { |key, code|
        begin
          v = pe.instance_eval(code)
          unless v.nil?
            metrics[key] = {'value' => v}
          end
        rescue
        end
      }

      # set each configruration limit
      buffer_queue_limit = pe.instance_eval('@buffer.buffer_queue_limit')
      metrics['buffer_queue_length']['max'] = buffer_queue_limit
      metrics['buffer_queued_size']['max'] = buffer_queue_limit * pe.instance_eval('@buffer.buffer_chunk_limit')

      metrics
    end
  end

  # Tag related extension for plugin identify

  module PluginId
    attr_accessor :tag_path

    def id_or_tag_path
      @id ? @id : @tag_path ? @tag_path : "object:#{object_id.to_s(16)}"
    end
  end

  class Match
    alias orig_init initialize
    attr_reader :pattern_str

    def initialize(pattern_str, output)
      @pattern_str = pattern_str.dup
      orig_init(pattern_str, output)
    end
  end

  class EngineClass
    def set_tag_path(prefix = '')
      @matches.each { |m|
        if m.is_a?(Match)
          tag_path = "#{prefix}/#{m.pattern_str}"
          m.output.tag_path = tag_path
          if m.output.is_a?(MultiOutput) && m.output.respond_to?(:outputs)
            set_tag_path_to_multi_output(tag_path, m.output)
          end
          if m.output.respond_to?(:output) && m.output.output.is_a?(Output)
            set_tag_path_to_wrap_output(tag_path, m.output)
          end
        end
      }
    end

    def set_tag_path_to_multi_output(prefix, multi_output)
      new_prefix = "#{prefix}/#{get_type_from_klass(multi_output.class)}"
      multi_output.outputs.each_with_index { |output, index|
        set_tag_path_to_output("#{new_prefix}.#{index}", output)
      }
    end

    def set_tag_path_to_wrap_output(prefix, wrap_output)
      new_prefix = "#{prefix}/#{get_type_from_klass(wrap_output.class)}"
      set_tag_path_to_output(new_prefix, wrap_output.output)
    end

    def set_tag_path_to_output(prefix, output)
      if output.is_a?(MultiOutput)
        set_tag_path_to_multi_output(prefix, output)
      else
        output.tag_path = "#{prefix}/#{get_type_from_klass(output.class)}"
      end
    end

    def get_type_from_klass(klass)
      Plugin.instance_variable_get(:@output).each { |name, output|
        return name if output == klass
      }
    end
  end
end