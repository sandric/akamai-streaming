Stupid overview
------------
Library to generate secure tokens for Akamai Live streaming service.

Stupid example
------------
```ruby
streaming = AkamaiStreaming.new(:key => 'your key in hexademical format')
streaming.encrypted_token
```

Stupid Testing
------------
```ruby
describe Stream do
  it_behaves_like "a akamai token generator" do
    let(:params){ Hash.new } #all your test params
    let(:generated_token){ streaming.encrypted_token } #pass method invoking token generator for comparising
  end
end
```
