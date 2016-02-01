# [Fluentd](http://fluentd.org) plugin for td monitoring

# Getting Started

## Fluentd

```sh
> gem install fluent-plugin-td-monitoring
```

## td-agent

```sh
> sudo /usr/lib64/fluent/ruby/bin/fluent-gem install fluent-plugin-td-monitoring 
```

## Testing with git repository

Use `-p` option to add plugin into search path. 

```sh
> fluentd -c fluentd.conf -p /path/to/fluent-plugin-td-monitoring/lib/fluent/plugin
```

# Supported Environment

* Fluentd v0.10.33 or later

  * corresponding td-agent is v1.1.13 or later

* Full features are supported on Linux.

  * system metrics is not supported on Mac and Windows.

# Configuration

td-monitoring plugin consists of two plugins, `td_monitor_agent` and `td_counter`.

## td_monitor_agent

This plugin collects node metrics and buffer metrics and send to TD-MONITORING service.

```conf
<source>
  type td_monitor_agent
  apikey YOUR_TREASURE_DATA_APIKEY
  instance_id aggregator1
</source>
```

* apikey

Your Treasure Data API key.

* instance_id

Specify unique instance id across nodes. If not specified, use configuration file path instead.

* disable_node_info (default true)

Send system metrics, CPU / Memory / Disk, or not.

## td_counter

This plugin collects event traffic per tag and collected results are send via `td_monitor_agent` plugin.
This plugin requires `td_monitor_agent` in same configuration.

```conf
<match apache.**>
   type td_counter

   <store>
     type file
     path /path/to/tmp/fluentd/log/apache.log
     time_slice_format %Y%m%d
     time_slice_wait 10m
     time_format %Y%m%dT%H%M%S%z
     buffer_type file
     buffer_path /path/to/tmp/fluentd/buffer/buf
   </store>
</match>
```

* `<store>`

This is an optinal configuration. If use `<store>`, `td_counter` passes received records into `<store>` plugin.
Only output plugin is available in `<store>`.

### NOTE

This plugin causes the performance degression because collecting the number of record and message bytes.
If you want to use this plugin on high traffic environment, please check the performance.

# Test for Development Environment

```sh
$ gem install fluentd
$ git clone git@github.com:treasure-data/fluent-plugin-td-monitoring.git
$ cd fluent-plugin-td-monitoring
$ bundle install
$ bundle exec rake build
$ gem install pkg/fluent-plugin-td-monitoring-*.gem
$ fluentd -c fluentd.conf
```

```conf
<source>
  type td_monitor_agent
  apikey YOUR_TREASURE_DATA_APIKEY
  instance_id aggregator0

  # for local testing
  emit_interval 10s
  endpoint http://127.0.0.1:3000/
  disable_node_info true  # for mac environment
</source>
<source>
  type forward
</source>
<match test.**>
  type forward
</match>
```

# TODO

- each instance metric of CPU / Memory
