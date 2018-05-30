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

    it 'accepts records with a valid sourceIpAddress' do
      subject.decode('{"Records":[{"sourceIpAddress":"111.22.3.3"}]}') do |event|
       expect(event.get("sourceIpAddress")).to eq("111.22.3.3")
       expect(event.get("sourceHost")).to be_nil
      end
    end

    it 'accepts records with an invalid sourceIpAddress' do
      subject.decode('{"Records":[{"sourceIpAddress":"www.elastic.co"}]}') do |event|
        expect(event.get("sourceIpAddress")).to be_nil
        expect(event.get("sourceHost")).to eq("www.elastic.co")
      end
    end

    it 'accepts records with a no sourceIpAddress' do
      subject.decode('{"Records":[{"sourceIpAddress":null}]}') do |event|
        expect(event.get("sourceIpAddress")).to be_nil
        expect(event.get("sourceHost")).to be_nil
      end
    end
  end
end
