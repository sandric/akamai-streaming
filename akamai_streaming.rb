require 'openssl'
require 'base64'

class AkamaiStreaming
  @attributes = {
    :start_time => Time.now.to_i,
    :window => 300,
    :algo => 'sha256',
    :key => 'aabbccddeeff00112233445566778899',
    :field_delimiter => '~',              
    :early_url_encoding => false,
    :debug => false,
    :acl => nil,
    :url => nil,
    :ip => nil,
    :session_id => nil,
    :data => nil,
    :salt => nil
  }.each {|attribute| attr_accessor(attribute.first)}

  @fields = {
    :start_time => 'st',
    :expiration_field => 'exp',
    :acl => 'acl',
    :url => 'url',
    :ip => 'ip',
    :session_id => 'id',
    :data => 'data',
    :salt => 'salt'
  }.each do |field_name, field_synonym|
    define_method("#{field_name}_field") do
      (self.send field_name) ? "#{field_synonym}=#{self.send field_name}#{field_delimiter}" : ''
    end
  end

  class << self
    attr_accessor :attributes, :fields
  end

  def initialize(params = {})
    self.class::attributes.each do |attribute, default_value|
      self.send "#{attribute}=", params.fetch(attribute, default_value)
    end

    self.class::attributes.each do |attribute, default_value|
      self.send "#{attribute}=", params.fetch(attribute, default_value)
    end
  end

  def start_time=(start_time)
    if start_time < 0 || start_time > 4294967295
      raise 'Invalid start time'
    else
      @start_time = start_time
    end
  end

  def key=(key)
    @key = hex_to_string(key)
  end

  def algo=(algo)
    if %w(md5 sha1 sha256).include?(algo)
      @algo = algo
    else
      raise 'Invalid crypto algorithm'
    end
  end

  def acl=(acl)
    if @url.nil?
      @acl = acl
    else
      raise 'Cannot set ACL with URL'
    end
  end

  def url=(url)
    if @acl.nil?
      @url = url
    else
      raise 'Cannot set URL with ACL'
    end
  end

  def expiration_field 
    "exp=#{(start_time + window)}#{field_delimiter}"
  end

  def acl_field
    if acl.nil? && url.nil?
      "#{self.class::fields[:acl]}=/*#{field_delimiter}"
    else
      "#{self.class::fields[:acl]}=#{acl}#{field_delimiter}"
    end
  end

  def raw_token
    ip_field + start_time_field + expiration_field + acl_field + session_id_field + data_field
  end

  def token_digest
    raw_token + url_field + salt_field
  end

  def trimmed_token_digest
    token_digest.chomp(field_delimiter)
  end

  def encrypted_token
    hmac = OpenSSL::HMAC.hexdigest('sha256', key, trimmed_token_digest)
    "#{raw_token}hmac=#{hmac}".gsub('/','%2f')
  end

  def hex_to_string(hex_string)
    stripped = hex_string.gsub(/\s+/,'')
    unless stripped.size % 2 == 0
      raise "Can't translate a string unless it has an even number of digits"
    end
    raise "Can't translate non-hex characters" if stripped =~ /[^0-9A-Fa-f]/
    res = [stripped].pack('H*')
    if RUBY_VERSION =~ /1.8/
      res
    else
      res.force_encoding("ascii-8bit")
    end
  end
end