# encoding: utf-8
require "logstash/codecs/base"
require "logstash/codecs/spool"
require "logstash/json"

# This is the base class for logstash codecs.
class LogStash::Codecs::CloudTrail < LogStash::Codecs::Spool
  config_name "cloudtrail"

  public
  def decode(data)
    super(LogStash::Json.load(data.force_encoding("UTF-8"))['Records']) do |event|
      event['@timestamp'] = event.delete('eventTime')

      if event.has_key?("requestParameters")
        if event['requestParameters'].has_key?("disableApiTermination")
          if event['requestParameters']['disableApiTermination'].class != Hash
            disableApiTermination = event['requestParameters'].delete('disableApiTermination')
            event['requestParameters']['disableApiTermination']= {"value" => disableApiTermination}
          end
        end
      end

      yield LogStash::Event.new(event)
    end
  end # def decode

end # class LogStash::Codecs::CloudTrail
