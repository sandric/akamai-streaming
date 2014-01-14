require_relative '../../lib/akamai_streaming'

describe AkamaiStreaming do

  let(:streaming){AkamaiStreaming.new}

  context 'when initialized with default parameters' do
    it 'should set window default value' do
      expect(streaming.window).to eq 300
    end

    it 'should set algo default value' do
      expect(streaming.algo).to eq 'sha256'
    end

    it 'should set field_delimiter value' do
      expect(streaming.field_delimiter).to eq '~'
    end

    it 'should set early_url_encoding default value' do
      expect(streaming.early_url_encoding).to eq false
    end

    it 'should set debug default value' do
      expect(streaming.debug).to eq false
    end

    it 'should generate default raw token' do
      expect(streaming.raw_token).to eq(streaming.start_time_field + streaming.expiration_field + streaming.acl_field)
    end

    it 'should generate default token digest' do
      expect(streaming.token_digest).to eq(streaming.raw_token)
    end

    it 'should generate default trimmed token digest' do
      expect(streaming.trimmed_token_digest).to eq(streaming.start_time_field + streaming.expiration_field + "#{AkamaiStreaming::fields[:acl]}=/*")
    end

    it 'should generate default encrypted token' do
      OpenSSL::HMAC.stub(:hexdigest){ 'test_hmac_value' }
      expect(streaming.encrypted_token).to eq("#{streaming.raw_token}hmac=test_hmac_value".gsub('/',"%2f"))
    end
  end

  it "should raise 'Invalid crypta algorithm' exception when trying to set invalid crypto algorithm" do
    streaming
    expect{ streaming.algo = 'sha128' }.to raise_exception 'Invalid crypto algorithm'
  end

  it "should raise 'Cannot set ACL with URL' exception when trying to set acl after url was set" do
    streaming
    streaming.url = 'http://example.com'
    expect{ streaming.acl = '/*' }.to raise_exception 'Cannot set ACL with URL'
  end

  it "should raise 'Cannot set URL with ACL' exception when trying to set url after acl was set" do
    streaming.acl = '/*'
    expect{ streaming.url = 'http://example.com' }.to raise_exception 'Cannot set URL with ACL'
  end

  it "should raise 'Invalid start time' exception when trying to set start_time less than zero" do
    expect{ streaming.start_time = -1 }.to raise_exception 'Invalid start time'
  end

  it "should raise 'Invalid start time' exception when trying to set start_time less more than 4294967295" do
    expect{ streaming.start_time = 4294967296 }.to raise_exception 'Invalid start time'
  end

  it 'should generate start_time_field' do
    streaming.start_time = 123
    expect(streaming.start_time_field).to eq('st=123~')
  end

  it 'should generate expiration_field' do
    streaming.start_time = 123
    streaming.window = 10
    expect(streaming.expiration_field).to eq('exp=133~')
  end

  it 'should generate acl_field' do
    streaming.acl = '/*'
    expect(streaming.acl_field).to eq('acl=/*~')
  end

  it 'should generate url_field' do
    streaming.url = 'http://example.com'
    expect(streaming.url_field).to eq('url=http://example.com~')
  end

  it 'should generate ip_field' do
    streaming.ip = '0.0.0.0'
    expect(streaming.ip_field).to eq('ip=0.0.0.0~')
  end

  it 'should generate session_id_field' do
    streaming.session_id = 'session_id'
    expect(streaming.session_id_field).to eq('id=session_id~')
  end

  it 'should generate data_field' do
    streaming.data = 'data'
    expect(streaming.data_field).to eq('data=data~')
  end

  it 'should generate salt_field' do
    streaming.salt = 'salt'
    expect(streaming.salt_field).to eq('salt=salt~')
  end

  it 'should generate salt_field' do
    streaming.salt = 'salt'
    expect(streaming.salt_field).to eq('salt=salt~')
  end
end

shared_examples_for "a akamai token generator" do
  #steraming key should be provided
  let(:streaming){ AkamaiStreaming.new params }

  it 'should generate default encrypted token' do
    OpenSSL::HMAC.stub(:hexdigest){ 'test_hmac_value' }
    expect(streaming.encrypted_token).to eq(generated_token)
  end
end