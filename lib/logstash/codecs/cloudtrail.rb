# encoding: utf-8
require "logstash/codecs/base"
require "logstash/json"
require "logstash/util/charset"

# This is the base class for logstash codecs.
class LogStash::Codecs::CloudTrail < LogStash::Codecs::Base
  config_name "cloudtrail"

  config :charset, :validate => ::Encoding.name_list, :default => "UTF-8"

  public
  def register
    @converter = LogStash::Util::Charset.new(@charset)
    @converter.logger = @logger
  end

  public
  def decode(data)
    decoded = LogStash::Json.load(@converter.convert(data))
    decoded['Records'].each do |event|
      event['@timestamp'] = event.delete('eventTime')
      yield LogStash::Event.new(event)
    end
  end # def decode

end # class LogStash::Codecs::CloudTrail
