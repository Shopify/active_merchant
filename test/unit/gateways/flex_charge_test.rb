require 'test_helper'

class FlexChargeTest < Test::Unit::TestCase
  include CommStub

  def setup
    @gateway = FlexChargeGateway.new(
      app_key: 'SOMECREDENTIAL',
      app_secret: 'SOMECREDENTIAL',
      site_id: 'SOMECREDENTIAL',
      mid: 'SOMECREDENTIAL'
    )
    @credit_card = credit_card
    @amount = 100

    @options = {
      is_declined: true,
      order_id: SecureRandom.uuid,
      idempotency_key: SecureRandom.uuid,
      card_not_present: true,
      email: 'test@gmail.com',
      response_code: '100',
      response_code_source: 'nmi',
      avs_result_code: '200',
      cvv_result_code: '111',
      cavv_result_code: '111',
      timezone_utc_offset: '-5',
      billing_address: address.merge(name: 'Cure Tester')
    }

    @cit_options = {
      is_mit: false,
      phone: '+99.2001a/+99.2001b'
    }.merge(@options)

    @mit_options = {
      is_mit: true,
      is_recurring: false,
      mit_expiry_date_utc: (Time.now + 1.day).getutc.iso8601,
      description: 'MyShoesStore'
    }.merge(@options)

    @mit_recurring_options = {
      is_recurring: true,
      subscription_id: SecureRandom.uuid,
      subscription_interval: 'monthly'
    }.merge(@mit_options)

    @tokenize_cit_options = @cit_options.merge(tokenize: true)

    @tokenize_mit_options = @mit_options.merge(tokenize: true)
  end

  def test_supported_countries
    assert_equal %w(US), FlexChargeGateway.supported_countries
  end

  def test_supported_cardtypes
    assert_equal %i[visa master american_express discover], @gateway.supported_cardtypes
  end

  def test_build_request_url_for_purchase
    action = :purchase
    assert_equal @gateway.send(:build_request_url, action), "#{@gateway.test_url}evaluate"
  end

  def test_build_request_url_with_id_param
    action = :refund
    id = 123
    assert_equal @gateway.send(:build_request_url, action, id), "#{@gateway.test_url}orders/123/refund"
  end

  def test_invalid_instance
    assert_raise ArgumentError do
      FlexChargeGateway.new()
    end
  end

  def test_successful_purchase
    response = stub_comms do
      @gateway.purchase(@amount, @credit_card, @options)
    end.check_request do |endpoint, data, headers|
      request = JSON.parse(data)

      if /token/.match?(endpoint)
        assert_equal request['AppKey'], @gateway.options[:app_key]
        assert_equal request['AppSecret'], @gateway.options[:app_secret]
      end

      if /evaluate/.match?(endpoint)
        assert_equal headers['Authorization'], "Bearer #{@gateway.options[:access_token]}"
        assert_equal request['siteId'], @gateway.options[:site_id]
        assert_equal request['mid'], @gateway.options[:mid]
        assert_equal request['isDeclined'], @options[:is_declined]
        assert_equal request['orderId'], @options[:order_id]
        assert_equal request['idempotencyKey'], @options[:idempotency_key]
        assert_equal request['transaction']['cardNotPresent'], @options[:card_not_present]
        assert_equal request['transaction']['timezoneUtcOffset'], @options[:timezone_utc_offset]
        assert_equal request['transaction']['amount'], @amount
        assert_equal request['transaction']['responseCode'], @options[:response_code]
        assert_equal request['transaction']['responseCodeSource'], @options[:response_code_source]
        assert_equal request['transaction']['avsResultCode'], @options[:avs_result_code]
        assert_equal request['transaction']['cvvResultCode'], @options[:cvv_result_code]
        assert_equal request['transaction']['cavvResultCode'], @options[:cavv_result_code]
        assert_equal request['payer']['email'], @options[:email]
        assert_equal request['description'], @options[:description]
      end
    end.respond_with(successful_access_token_response, successful_purchase_response)

    assert_success response

    assert_equal 'ca7bb327-a750-412d-a9c3-050d72b3f0c5', response.authorization
    assert response.test?
  end

  def test_failed_purchase
    response = stub_comms do
      @gateway.purchase(@amount, @credit_card, @options)
    end.check_request do |endpoint, data, _headers|
      request = JSON.parse(data)

      if /token/.match?(endpoint)
        assert_equal request['AppKey'], @gateway.options[:app_key]
        assert_equal request['AppSecret'], @gateway.options[:app_secret]
      end
    end.respond_with(successful_access_token_response, failed_purchase_response)

    assert_failure response
    assert_equal '400', response.error_code
  end

  def test_successful_authorize; end

  def test_failed_authorize; end

  def test_successful_capture; end

  def test_failed_capture; end

  def test_successful_refund; end

  def test_failed_refund
    response = stub_comms do
      @gateway.refund(@amount, 'reference', @options)
    end.check_request do |endpoint, data, _headers|
      request = JSON.parse(data)

      if /token/.match?(endpoint)
        assert_equal request['AppKey'], @gateway.options[:app_key]
        assert_equal request['AppSecret'], @gateway.options[:app_secret]
      end

      assert_equal request['amountToRefund'], sprintf('%.2f', @amount.to_f / 100) if /orders\/reference\/refund/.match?(endpoint)
    end.respond_with(successful_access_token_response, failed_refund_response)

    assert_failure response
    assert response.test?
  end

  def test_successful_void; end

  def test_failed_void; end

  def test_successful_verify; end

  def test_successful_verify_with_failed_void; end

  def test_failed_verify; end

  def test_scrub
    assert @gateway.supports_scrubbing?
    assert_equal @gateway.scrub(pre_scrubbed), post_scrubbed
  end

  private

  def pre_scrubbed
    "opening connection to api-sandbox.flex-charge.com:443...
    opened
    starting SSL for api-sandbox.flex-charge.com:443...
    SSL established, protocol: TLSv1.3, cipher: TLS_AES_128_GCM_SHA256
    <- \"POST /v1/oauth2/token HTTP/1.1\\r\
    Content-Type: application/json\\r\
    Connection: close\\r\
    Accept-Encoding: gzip;q=1.0,deflate;q=0.6,identity;q=0.3\\r\
    Accept: */*\\r\
    User-Agent: Ruby\\r\
    Host: api-sandbox.flex-charge.com\\r\
    Content-Length: 153\\r\
    \\r\
    \"
    <- \"{\\\"AppKey\\\":\\\"2/tprAqlvujvIZonWkLntQMj3CbH7Y9sKLqTTdWu\\\",\\\"AppSecret\\\":\\\"AQAAAAEAACcQAAAAEFb/TYEfAlzWhb6SDXEbS06A49kc/P6Cje6 MDta3o61GGS4tLLk8m/BZuJOyZ7B99g==\\\"}\"
    -> \"HTTP/1.1 200 OK\\r\
    \"
    -> \"Date: Thu, 04 Apr 2024 13:29:08 GMT\\r\
    \"
    -> \"Content-Type: application/json; charset=utf-8\\r\
    \"
    -> \"Content-Length: 902\\r\
    \"
    -> \"Connection: close\\r\
    \"
    -> \"server: Kestrel\\r\
    \"
    -> \"set-cookie: AWSALB=n2vt9daKLxUPgxF+n3g+4uQDgxt1PNVOY/HwVuLZdkf0Ye8XkAFuEVrnu6xh/xf7k2ZYZHqaPthqR36D3JxPJIs7QfNbcfAhvxTlPEVx8t/IyB1Kb/Vinasi3vZD; Expires=Thu, 11 Apr 2024 13:29:08 GMT; Path=/\\r\
    \"
    -> \"set-cookie: AWSALBCORS=n2vt9daKLxUPgxF+n3g+4uQDgxt1PNVOY/HwVuLZdkf0Ye8XkAFuEVrnu6xh/xf7k2ZYZHqaPthqR36D3JxPJIs7QfNbcfAhvxTlPEVx8t/IyB1Kb/Vinasi3vZD; Expires=Thu, 11 Apr 2024 13:29:08 GMT; Path=/; SameSite=None; Secure\\r\
    \"
    -> \"apigw-requestid: Vs-twgfMoAMEaEQ=\\r\
    \"
    -> \"\\r\
    \"
    reading 902 bytes...
    -> \"{\\\"accessToken\\\":\\\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwYmE4NGY2ZS03YTllLTQzZjEtYWU2ZC1jNTA4YjQ2NjQyNGEiLCJ1bmlxdWVfbmFtZSI6IjBiYTg0ZjZlLTdhOWUtNDNmMS1hZTZkLWM1MDhiNDY2NDI0YSIsImp0aSI6IjI2NTQxY2FlLWM3ZjUtNDU0MC04MTUyLTZiNGExNzQ3ZTJmMSIsImlhdCI6IjE3MTIyMzczNDg1NjUiLCJhdWQiOlsicGF5bWVudHMiLCJvcmRlcnMiLCJtZXJjaGFudHMiLCJlbGlnaWJpbGl0eS1zZnRwIiwiZWxpZ2liaWxpdHkiLCJjb250YWN0Il0sImN1c3RvbTptaWQiOiJkOWQwYjVmZC05NDMzLTQ0ZDMtODA1MS02M2ZlZTI4NzY4ZTgiLCJuYmYiOjE3MTIyMzczNDgsImV4cCI6MTcxMjIzNzk0OCwiaXNzIjoiQXBpLUNsaWVudC1TZXJ2aWNlIn0.ZGYzd6NA06o2zP-qEWf6YpyrY-v-Jb-i1SGUOUkgRPo\\\",\\\"refreshToken\\\":\\\"AQAAAAEAACcQAAAAEG5H7emaTnpUcVSWrbwLlPBEEdQ3mTCCHT5YMLBNauXxilaXHwL8oFiI4heg6yA\\\",\\\"expires\\\":1712237948565,\\\"id\\\":\\\"0ba84f6e-7a9e-43f1-ae6d-c508b466424a\\\",\\\"session\\\":null,\\\"daysToEnforceMFA\\\":null,\\\"skipAvailable\\\":null,\\\"success\\\":true,\\\"result\\\":null,\\\"status\\\":null,\\\"statusCode\\\":null,\\\"errors\\\":[],\\\"customProperties\\\":{}}\"
    read 902 bytes
    Conn close
    opening connection to api-sandbox.flex-charge.com:443...
    opened
    starting SSL for api-sandbox.flex-charge.com:443...
    SSL established, protocol: TLSv1.3, cipher: TLS_AES_128_GCM_SHA256
    <- \"POST /v1/evaluate HTTP/1.1\\r\
    Content-Type: application/json\\r\
    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwYmE4NGY2ZS03YTllLTQzZjEtYWU2ZC1jNTA4YjQ2NjQyNGEiLCJ1bmlxdWVfbmFtZSI6IjBiYTg0ZjZlLTdhOWUtNDNmMS1hZTZkLWM1MDhiNDY2NDI0YSIsImp0aSI6IjI2NTQxY2FlLWM3ZjUtNDU0MC04MTUyLTZiNGExNzQ3ZTJmMSIsImlhdCI6IjE3MTIyMzczNDg1NjUiLCJhdWQiOlsicGF5bWVudHMiLCJvcmRlcnMiLCJtZXJjaGFudHMiLCJlbGlnaWJpbGl0eS1zZnRwIiwiZWxpZ2liaWxpdHkiLCJjb250YWN0Il0sImN1c3RvbTptaWQiOiJkOWQwYjVmZC05NDMzLTQ0ZDMtODA1MS02M2ZlZTI4NzY4ZTgiLCJuYmYiOjE3MTIyMzczNDgsImV4cCI6MTcxMjIzNzk0OCwiaXNzIjoiQXBpLUNsaWVudC1TZXJ2aWNlIn0.ZGYzd6NA06o2zP-qEWf6YpyrY-v-Jb-i1SGUOUkgRPo\\r\
    Connection: close\\r\
    Accept-Encoding: gzip;q=1.0,deflate;q=0.6,identity;q=0.3\\r\
    Accept: */*\\r\
    User-Agent: Ruby\\r\
    Host: api-sandbox.flex-charge.com\\r\
    Content-Length: 999\\r\
    \\r\
    \"
    <- \"{\\\"siteId\\\":\\\"ffae80fd-2b8e-487a-94c3-87503a0c71bb\\\",\\\"mid\\\":\\\"d9d0b5fd-9433-44d3-8051-63fee28768e8\\\",\\\"isDeclined\\\":true,\\\"orderId\\\":\\\"b53827df-1f19-4dd9-9829-25a108255ba1\\\",\\\"idempotencyKey\\\":\\\"46902e30-ae70-42c5-a0d3-1994133b4f52\\\",\\\"transaction\\\":{\\\"id\\\":\\\"b53827df-1f19-4dd9-9829-25a108255ba1\\\",\\\"dynamicDescriptor\\\":\\\"MyShoesStore\\\",\\\"timezoneUtcOffset\\\":\\\"-5\\\",\\\"amount\\\":100,\\\"currency\\\":\\\"USD\\\",\\\"responseCode\\\":\\\"100\\\",\\\"responseCodeSource\\\":\\\"nmi\\\",\\\"avsResultCode\\\":\\\"200\\\",\\\"cvvResultCode\\\":\\\"111\\\",\\\"cavvResultCode\\\":\\\"111\\\",\\\"cardNotPresent\\\":true},\\\"paymentMethod\\\":{\\\"holderName\\\":\\\"Longbob Longsen\\\",\\\"cardType\\\":\\\"CREDIT\\\",\\\"cardBrand\\\":\\\"VISA\\\",\\\"cardCountry\\\":\\\"CA\\\",\\\"expirationMonth\\\":9,\\\"expirationYear\\\":2025,\\\"cardBinNumber\\\":\\\"411111\\\",\\\"cardLast4Digits\\\":\\\"1111\\\",\\\"cardNumber\\\":\\\"4111111111111111\\\"},\\\"billingInformation\\\":{\\\"firstName\\\":\\\"Cure\\\",\\\"lastName\\\":\\\"Tester\\\",\\\"country\\\":\\\"CA\\\",\\\"phone\\\":\\\"(555)555-5555\\\",\\\"countryCode\\\":\\\"CA\\\",\\\"addressLine1\\\":\\\"456 My Street\\\",\\\"state\\\":\\\"ON\\\",\\\"city\\\":\\\"Ottawa\\\",\\\"zipCode\\\":\\\"K1C2N6\\\"},\\\"payer\\\":{\\\"email\\\":\\\"test@gmail.com\\\",\\\"phone\\\":\\\"+99.2001a/+99.2001b\\\"}}\"
    -> \"HTTP/1.1 200 OK\\r\
    \"
    -> \"Date: Thu, 04 Apr 2024 13:29:11 GMT\\r\
    \"
    -> \"Content-Type: application/json; charset=utf-8\\r\
    \"
    -> \"Content-Length: 230\\r\
    \"
    -> \"Connection: close\\r\
    \"
    -> \"server: Kestrel\\r\
    \"
    -> \"set-cookie: AWSALB=Mw7gQis/D9qOm0eQvpkNsEOvZerr+YBDNyfJyJ2T2BGel3cg8AX9OtpuXXR/UCCgNRf5J9UTY+soHqLEJuxIEdEK5lNPelLtQbO0oKGB12q0gPRI7T5H1ijnf+RF; Expires=Thu, 11 Apr 2024 13:29:08 GMT; Path=/\\r\
    \"
    -> \"set-cookie: AWSALBCORS=Mw7gQis/D9qOm0eQvpkNsEOvZerr+YBDNyfJyJ2T2BGel3cg8AX9OtpuXXR/UCCgNRf5J9UTY+soHqLEJuxIEdEK5lNPelLtQbO0oKGB12q0gPRI7T5H1ijnf+RF; Expires=Thu, 11 Apr 2024 13:29:08 GMT; Path=/; SameSite=None; Secure\\r\
    \"
    -> \"apigw-requestid: Vs-t0g9gIAMES8w=\\r\
    \"
    -> \"\\r\
    \"
    reading 230 bytes...
    -> \"{\\\"orderSessionKey\\\":\\\"e97b1ff1-4449-46da-bc6c-a76d23f16353\\\",\\\"senseKey\\\":null,\\\"orderId\\\":\\\"e97b1ff1-4449-46da-bc6c-a76d23f16353\\\",\\\"success\\\":true,\\\"result\\\":\\\"Success\\\",\\\"status\\\":\\\"CHALLENGE\\\",\\\"statusCode\\\":null,\\\"errors\\\":[],\\\"customProperties\\\":{}}\"
    read 230 bytes
    Conn close
    "
  end

  def post_scrubbed
    "opening connection to api-sandbox.flex-charge.com:443...
    opened
    starting SSL for api-sandbox.flex-charge.com:443...
    SSL established, protocol: TLSv1.3, cipher: TLS_AES_128_GCM_SHA256
    <- \"POST /v1/oauth2/token HTTP/1.1\\r\
    Content-Type: application/json\\r\
    Connection: close\\r\
    Accept-Encoding: gzip;q=1.0,deflate;q=0.6,identity;q=0.3\\r\
    Accept: */*\\r\
    User-Agent: Ruby\\r\
    Host: api-sandbox.flex-charge.com\\r\
    Content-Length: 153\\r\
    \\r\
    \"
    <- \"{\\\"AppKey\\\":\\\"[FILTERED]\",\\\"AppSecret\\\":\\\"[FILTERED]\"}\"
    -> \"HTTP/1.1 200 OK\\r\
    \"
    -> \"Date: Thu, 04 Apr 2024 13:29:08 GMT\\r\
    \"
    -> \"Content-Type: application/json; charset=utf-8\\r\
    \"
    -> \"Content-Length: 902\\r\
    \"
    -> \"Connection: close\\r\
    \"
    -> \"server: Kestrel\\r\
    \"
    -> \"set-cookie: AWSALB=n2vt9daKLxUPgxF+n3g+4uQDgxt1PNVOY/HwVuLZdkf0Ye8XkAFuEVrnu6xh/xf7k2ZYZHqaPthqR36D3JxPJIs7QfNbcfAhvxTlPEVx8t/IyB1Kb/Vinasi3vZD; Expires=Thu, 11 Apr 2024 13:29:08 GMT; Path=/\\r\
    \"
    -> \"set-cookie: AWSALBCORS=n2vt9daKLxUPgxF+n3g+4uQDgxt1PNVOY/HwVuLZdkf0Ye8XkAFuEVrnu6xh/xf7k2ZYZHqaPthqR36D3JxPJIs7QfNbcfAhvxTlPEVx8t/IyB1Kb/Vinasi3vZD; Expires=Thu, 11 Apr 2024 13:29:08 GMT; Path=/; SameSite=None; Secure\\r\
    \"
    -> \"apigw-requestid: Vs-twgfMoAMEaEQ=\\r\
    \"
    -> \"\\r\
    \"
    reading 902 bytes...
    -> \"{\\\"accessToken\\\":\\\"[FILTERED]\",\\\"refreshToken\\\":\\\"AQAAAAEAACcQAAAAEG5H7emaTnpUcVSWrbwLlPBEEdQ3mTCCHT5YMLBNauXxilaXHwL8oFiI4heg6yA\\\",\\\"expires\\\":1712237948565,\\\"id\\\":\\\"0ba84f6e-7a9e-43f1-ae6d-c508b466424a\\\",\\\"session\\\":null,\\\"daysToEnforceMFA\\\":null,\\\"skipAvailable\\\":null,\\\"success\\\":true,\\\"result\\\":null,\\\"status\\\":null,\\\"statusCode\\\":null,\\\"errors\\\":[],\\\"customProperties\\\":{}}\"
    read 902 bytes
    Conn close
    opening connection to api-sandbox.flex-charge.com:443...
    opened
    starting SSL for api-sandbox.flex-charge.com:443...
    SSL established, protocol: TLSv1.3, cipher: TLS_AES_128_GCM_SHA256
    <- \"POST /v1/evaluate HTTP/1.1\\r\
    Content-Type: application/json\\r\
    Authorization: Bearer [FILTERED]\\r\
    Connection: close\\r\
    Accept-Encoding: gzip;q=1.0,deflate;q=0.6,identity;q=0.3\\r\
    Accept: */*\\r\
    User-Agent: Ruby\\r\
    Host: api-sandbox.flex-charge.com\\r\
    Content-Length: 999\\r\
    \\r\
    \"
    <- \"{\\\"siteId\\\":\\\"[FILTERED]\",\\\"mid\\\":\\\"[FILTERED]\",\\\"isDeclined\\\":true,\\\"orderId\\\":\\\"b53827df-1f19-4dd9-9829-25a108255ba1\\\",\\\"idempotencyKey\\\":\\\"46902e30-ae70-42c5-a0d3-1994133b4f52\\\",\\\"transaction\\\":{\\\"id\\\":\\\"b53827df-1f19-4dd9-9829-25a108255ba1\\\",\\\"dynamicDescriptor\\\":\\\"MyShoesStore\\\",\\\"timezoneUtcOffset\\\":\\\"-5\\\",\\\"amount\\\":100,\\\"currency\\\":\\\"USD\\\",\\\"responseCode\\\":\\\"100\\\",\\\"responseCodeSource\\\":\\\"nmi\\\",\\\"avsResultCode\\\":\\\"200\\\",\\\"cvvResultCode\\\":\\\"111\\\",\\\"cavvResultCode\\\":\\\"111\\\",\\\"cardNotPresent\\\":true},\\\"paymentMethod\\\":{\\\"holderName\\\":\\\"Longbob Longsen\\\",\\\"cardType\\\":\\\"CREDIT\\\",\\\"cardBrand\\\":\\\"VISA\\\",\\\"cardCountry\\\":\\\"CA\\\",\\\"expirationMonth\\\":9,\\\"expirationYear\\\":2025,\\\"cardBinNumber\\\":\\\"411111\\\",\\\"cardLast4Digits\\\":\\\"1111\\\",\\\"cardNumber\\\":\\\"[FILTERED]\"},\\\"billingInformation\\\":{\\\"firstName\\\":\\\"Cure\\\",\\\"lastName\\\":\\\"Tester\\\",\\\"country\\\":\\\"CA\\\",\\\"phone\\\":\\\"(555)555-5555\\\",\\\"countryCode\\\":\\\"CA\\\",\\\"addressLine1\\\":\\\"456 My Street\\\",\\\"state\\\":\\\"ON\\\",\\\"city\\\":\\\"Ottawa\\\",\\\"zipCode\\\":\\\"K1C2N6\\\"},\\\"payer\\\":{\\\"email\\\":\\\"test@gmail.com\\\",\\\"phone\\\":\\\"+99.2001a/+99.2001b\\\"}}\"
    -> \"HTTP/1.1 200 OK\\r\
    \"
    -> \"Date: Thu, 04 Apr 2024 13:29:11 GMT\\r\
    \"
    -> \"Content-Type: application/json; charset=utf-8\\r\
    \"
    -> \"Content-Length: 230\\r\
    \"
    -> \"Connection: close\\r\
    \"
    -> \"server: Kestrel\\r\
    \"
    -> \"set-cookie: AWSALB=Mw7gQis/D9qOm0eQvpkNsEOvZerr+YBDNyfJyJ2T2BGel3cg8AX9OtpuXXR/UCCgNRf5J9UTY+soHqLEJuxIEdEK5lNPelLtQbO0oKGB12q0gPRI7T5H1ijnf+RF; Expires=Thu, 11 Apr 2024 13:29:08 GMT; Path=/\\r\
    \"
    -> \"set-cookie: AWSALBCORS=Mw7gQis/D9qOm0eQvpkNsEOvZerr+YBDNyfJyJ2T2BGel3cg8AX9OtpuXXR/UCCgNRf5J9UTY+soHqLEJuxIEdEK5lNPelLtQbO0oKGB12q0gPRI7T5H1ijnf+RF; Expires=Thu, 11 Apr 2024 13:29:08 GMT; Path=/; SameSite=None; Secure\\r\
    \"
    -> \"apigw-requestid: Vs-t0g9gIAMES8w=\\r\
    \"
    -> \"\\r\
    \"
    reading 230 bytes...
    -> \"{\\\"orderSessionKey\\\":\\\"e97b1ff1-4449-46da-bc6c-a76d23f16353\\\",\\\"senseKey\\\":null,\\\"orderId\\\":\\\"e97b1ff1-4449-46da-bc6c-a76d23f16353\\\",\\\"success\\\":true,\\\"result\\\":\\\"Success\\\",\\\"status\\\":\\\"CHALLENGE\\\",\\\"statusCode\\\":null,\\\"errors\\\":[],\\\"customProperties\\\":{}}\"
    read 230 bytes
    Conn close
    "
  end

  def successful_access_token_response
    <<~RESPONSE
      {
        "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwYmE4NGY2ZS03YTllLTQzZjEtYWU2ZC1jNTA4YjQ2NjQyNGEiLCJ1bmlxdWVfbmFtZSI6IjBiYTg0ZjZlLTdhOWUtNDNmMS1hZTZkLWM1MDhiNDY2NDI0YSIsImp0aSI6ImY5NzdlZDE3LWFlZDItNGIxOC1hMjY1LWY0NzkwNTY0ZDc1NSIsImlhdCI6IjE3MTIwNzE1NDMyNDYiLCJhdWQiOlsicGF5bWVudHMiLCJvcmRlcnMiLCJtZXJjaGFudHMiLCJlbGlnaWJpbGl0eS1zZnRwIiwiZWxpZ2liaWxpdHkiLCJjb250YWN0Il0sImN1c3RvbTptaWQiOiJkOWQwYjVmZC05NDMzLTQ0ZDMtODA1MS02M2ZlZTI4NzY4ZTgiLCJuYmYiOjE3MTIwNzE1NDMsImV4cCI6MTcxMjA3MjE0MywiaXNzIjoiQXBpLUNsaWVudC1TZXJ2aWNlIn0.S9xgOejudB93Gf9Np9S8jtudhbY9zJj_j7n5al_SKZg",
        "refreshToken": "AQAAAAEAACcQAAAAEKd3NvUOrqgJXW8FtE22UbdZzuMWcbq7kSMIGss9OcV2aGzCXMNrOJgAW5Zg",
        "expires": #{(DateTime.now + 10.minutes).strftime('%Q').to_i},
        "id": "0ba84f6e-7a9e-43f1-ae6d-c508b466424a",
        "session": null,
        "daysToEnforceMFA": null,
        "skipAvailable": null,
        "success": true,
        "result": null,
        "status": null,
        "statusCode": null,
        "errors": [],
        "customProperties": {}
      }
    RESPONSE
  end

  def successful_purchase_response
    <<~RESPONSE
      {
        "orderSessionKey": "ca7bb327-a750-412d-a9c3-050d72b3f0c5",
        "senseKey": null,
        "orderId": "ca7bb327-a750-412d-a9c3-050d72b3f0c5",
        "success": true,
        "result": "Success",
        "status": "CHALLENGE",
        "statusCode": null,
        "errors": [],
        "customProperties": {}
      }
    RESPONSE
  end

  def failed_purchase_response
    <<~RESPONSE
      {
        "status": "400",
        "errors": {
          "OrderId": ["Merchant's orderId is required"],
           "TraceId": ["00-3b4af05c51be4aa7dd77104ac75f252b-004c728c64ca280d-01"],
           "IsDeclined": ["The IsDeclined field is required."],
           "IdempotencyKey": ["The IdempotencyKey field is required."],
           "Transaction.Id": ["The Id field is required."],
           "Transaction.ResponseCode": ["The ResponseCode field is required."],
           "Transaction.AvsResultCode": ["The AvsResultCode field is required."],
           "Transaction.CvvResultCode": ["The CvvResultCode field is required."]
        }
      }
    RESPONSE
  end

  def successful_authorize_response; end

  def failed_authorize_response; end

  def successful_capture_response; end

  def failed_capture_response; end

  def successful_refund_response; end

  def failed_refund_response
    <<~RESPONSE
      {
        "responseCode": "2001",
        "responseMessage": "Amount to refund (1.00) is greater than maximum refund amount in (0.00))",
        "transactionId": null,
        "success": false,
        "result": null,
        "status": "FAILED",
        "statusCode": null,
        "errors": [
          {
            "item1": "Amount to refund (1.00) is greater than maximum refund amount in (0.00))",
            "item2": "2001",
            "item3": "2001",
            "item4": true
          }
        ],
        "customProperties": {}
      }
    RESPONSE
  end

  def successful_void_response; end

  def failed_void_response; end
end
