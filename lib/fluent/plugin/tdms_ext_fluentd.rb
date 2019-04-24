require 'fluent/plugin/in_monitor_agent'

module Fluent::Plugin
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
      'buffer_type' => '@buffer_config[:@type]',
      'buffer_path' => '@buffer.path',
      'flush_interval' => '@buffer_config.flush_interval')
    %W(plugin_id config buffer_queue_length buffer_total_queued_size retry_count buffer_timekeys).each { |k|
      TD_MONITOR_INFO.delete(k)
    }

    TD_PLUGIN_METRIC_INFO = { 
      'buffer_queue_length' => ->(){ throw(:skip) unless instance_variable_defined?(:@buffer) && !@buffer.nil? && @buffer.is_a?(::Fluent::Plugin::Buffer); @buffer.queue.size },
      'buffer_queued_size' => ->(){ throw(:skip) unless instance_variable_defined?(:@buffer) && !@buffer.nil? && @buffer.is_a?(::Fluent::Plugin::Buffer); @buffer.stage_size + @buffer.queue_size },
      'emit_count' => ->(){ @emit_count },
      'retry_count' => ->(){
        throw(:skip) unless instance_variable_defined?(:@buffer) && !@buffer.nil? && @buffer.is_a?(::Fluent::Plugin::Buffer)
        begin
          @retry ? @retry.steps : 0
        rescue
          0
        end
      },
    }

    def get_monitor_info(pe, opts = {})
      obj = {'plugin_id'.freeze => pe.plugin_id}
      conf = {
        'type'.freeze => pe.config['@type'.freeze] || pe.config['type'.freeze],
        'output_plugin'.freeze => pe.is_a?(::Fluent::Plugin::Output),
        'plugin_category'.freeze => plugin_category(pe)
      }

      if pe.is_a?(::Fluent::Plugin::Output) && pe.instance_variable_get(:@buffering)
        TD_MONITOR_INFO.each_pair { |key, code|
          begin
            v = pe.instance_eval(code)
            unless v.nil?
              conf[key] = v
            end
          rescue
          end
        }
        obj['metrics'] = get_plugin_metric(pe)
      end
      obj['config'] = conf

      obj
    end

    def get_plugin_metric(pe)
      metrics = {}
      TD_PLUGIN_METRIC_INFO.each_pair { |key, code|
        begin
          v = pe.instance_exec(&code)
          unless v.nil?
            metrics[key] = {'value' => v}
          end
        rescue
        end
      }

      # set each configruration limit
      total_size = pe.instance_eval('@buffer.total_limit_size')
      metrics['buffer_queue_length']['max'] = total_size / pe.instance_eval('@buffer.chunk_limit_size')
      metrics['buffer_queued_size']['max'] = total_size

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
end
