require "logstash/devutils/rspec/spec_helper"
require "logstash/plugin"
require "logstash/codecs/cloudtrail"

describe LogStash::Codecs::CloudTrail do

  describe '#decode' do
    it 'accepts data without a Records property' do
      expect { |b|
        subject.decode('{}', &b)
      }.not_to yield_control
    end

    it 'accepts records with null requestParameters' do
      expect { |b|
        subject.decode('{"Records":[{"requestParameters":null}]}', &b)
      }.to yield_control
    end
  end
end
