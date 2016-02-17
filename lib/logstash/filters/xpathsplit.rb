# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

class LogStash::Filters::Xpathsplit < LogStash::Filters::Base

  config_name "xpathsplit"

  config :source, :validate => :string, :required => true
  config :xpath_select, :validate => :string, :required => true
  config :xpath_extract, :validate => :hash, :default => {}
  config :namespaces, :validate => :hash, :default => {}
  config :remove_namespaces, :validate => :boolean, :default => false

  XMLPARSEFAILURE_TAG = "_xmlparsefailure"

  def register
    require "nokogiri"
    require "xmlsimple"
  end

  def filter(event)
    matched = false

    @logger.debug? && @logger.debug("Running XPath Subdoc filter", :event => event)

    value = event[@source]
    return unless value

    if value.is_a?(Array)
      if value.length != 1
        event.tag(XMLPARSEFAILURE_TAG)
        @logger.warn("XPath Subdoc filter expects single item array", :source => @source, :value => value)
        return
      end

      value = value.first
    end

    unless value.is_a?(String)
      event.tag(XMLPARSEFAILURE_TAG)
      @logger.warn("XPath Subdoc filter expects a string but received a #{value.class}", :source => @source, :value => value)
      return
    end

    # Do nothing with an empty string.
    return if value.strip.empty?

    if @xpath_select
      begin
        doc = Nokogiri::XML(value, nil, value.encoding.to_s, Nokogiri::XML::ParseOptions::DEFAULT_XML|Nokogiri::XML::ParseOptions::NOBLANKS)
      rescue => e
        event.tag(XMLPARSEFAILURE_TAG)
        @logger.warn("Error parsing xml", :source => @source, :value => value, :exception => e, :backtrace => e.backtrace)
        return
      end
      doc.remove_namespaces! if @remove_namespaces

      doc.xpath(@xpath_select).each do |subdoc|
        subevent = event.clone

        @xpath_extract.each do |xpath_src, xpath_dest|
          nodeset = @namespaces.empty? ? subdoc.xpath(xpath_src) : subdoc.xpath(xpath_src, @namespaces)
          normalized_nodeset = nodeset.kind_of?(Nokogiri::XML::NodeSet) ? nodeset : [nodeset]

          normalized_nodeset.each do |value|
            return if value.is_a?(Array) && value.length == 0
            if value
              subevent[xpath_dest] = value.to_s
            end
          end
        end
     
        filter_matched(event)
        yield subevent
      end

    end
    event.cancel
    @logger.debug? && @logger.debug("Event after XPath Subdoc filter", :event => event)
  end
end
