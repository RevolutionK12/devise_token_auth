require 'test_helper'

#  was the web request successful?
#  was the user redirected to the right page?
#  was the user successfully authenticated?
#  was the correct object stored in the response?
#  was the appropriate message delivered in the json payload?

class DemoUserControllerTest < ActionDispatch::IntegrationTest
  include Warden::Test::Helpers
  describe DemoUserController do
    describe "Token access" do
      before do
        @resource = users(:confirmed_email_user)
        @resource.skip_confirmation!
        @resource.save!

        @auth_headers = @resource.create_new_auth_token

        @token     = @auth_headers['access-token']
        @client_id = @auth_headers['client']
        @expiry    = @auth_headers['expiry']
      end

      describe 'successful request' do
        before do
          # ensure that request is not treated as batch request
          age_token(@resource, @client_id)

          get '/demo/members_only', {}, @auth_headers

          @resp_token       = response.headers['access-token']
          @resp_client_id   = response.headers['client']
          @resp_expiry      = response.headers['expiry']
        end

        describe 'devise mappings' do
          it 'should define current_user' do
            assert_equal @resource, @controller.current_user
          end

          it 'should define user_signed_in?' do
            assert @controller.user_signed_in?
          end

          it 'should not define current_mang' do
            refute_equal @resource, @controller.current_mang
          end
        end

        it 'should return success status' do
          assert_equal 200, response.status
        end

        it 'should receive new token after successful request' do
          refute_equal @token, @resp_token
        end

        it 'should preserve the client id from the first request' do
          assert_equal @client_id, @resp_client_id
        end

        it 'should not treat this request as a batch request' do
          refute assigns(:is_batch_request)
        end

        describe 'subsequent requests' do
          before do
            @resource.reload
            # ensure that request is not treated as batch request
            age_token(@resource, @client_id)

            get '/demo/members_only', {}, @auth_headers.merge({'access-token' => @resp_token})
          end

          it 'should not treat this request as a batch request' do
            refute assigns(:is_batch_request)
          end

          it "should allow a new request to be made using new token" do
            assert_equal 200, response.status
          end
        end
      end

      describe 'failed request' do
        before do
          get '/demo/members_only', {}, @auth_headers.merge({'access-token' => "bogus"})
        end

        it 'should not return any auth headers' do
          refute response.headers['access-token']
        end

        it 'should return error: unauthorized status' do
          assert_equal 401, response.status
        end
      end

      describe 'successful password change' do
        before do
          DeviseTokenAuth.remove_tokens_after_password_reset = true

          # adding one more token to simulate another logged in device
          @old_auth_headers = @auth_headers
          @auth_headers = @resource.create_new_auth_token
          age_token(@resource, @client_id)
          assert @resource.tokens.count > 1

          # password changed from new device
          @resource.update_attributes({
            password: 'newsecret123',
            password_confirmation: 'newsecret123'
          })

          get '/demo/members_only', {}, @auth_headers
        end

        after do
          DeviseTokenAuth.remove_tokens_after_password_reset = false
        end

        it 'should have only one token' do
          assert_equal 1, @resource.tokens.count
        end

        it 'new request should be successful' do
          assert 200, response.status
        end

        describe 'another device should not be able to login' do

          it 'should return forbidden status' do
            get '/demo/members_only', {}, @old_auth_headers
            assert 401, response.status
          end

        end

      end

      describe 'request including destroy of token' do
        describe 'when change_headers_on_each_request is set to false' do
          before do
            DeviseTokenAuth.change_headers_on_each_request = false
            age_token(@resource, @client_id)

            get '/demo/members_only_remove_token', {}, @auth_headers
          end

          after do
            DeviseTokenAuth.change_headers_on_each_request = true
          end

          it 'should not return auth-headers' do
            refute response.headers['access-token']
          end
        end

        describe 'when change_headers_on_each_request is set to true' do
          before do
            age_token(@resource, @client_id)
            get '/demo/members_only_remove_token', {}, @auth_headers
          end

          it 'should not return auth-headers' do
            refute response.headers['access-token']
          end
        end
      end

      describe 'when access-token name has been changed' do
        before do
          # ensure that request is not treated as batch request
          DeviseTokenAuth.headers_names[:'access-token'] = 'new-access-token'
          auth_headers_modified = @resource.create_new_auth_token
          client_id = auth_headers_modified['client']
          age_token(@resource, client_id)

          get '/demo/members_only', {}, auth_headers_modified
          @resp_token = response.headers['new-access-token']
        end

        it 'should have "new-access-token" header' do
          assert @resp_token.present?
        end

        after do
          DeviseTokenAuth.headers_names[:'access-token'] = 'access-token'
        end
      end
    end

    describe 'enable_standard_devise_support' do

      before do
        @resource = users(:confirmed_email_user)
        @auth_headers = @resource.create_new_auth_token
        DeviseTokenAuth.enable_standard_devise_support = true
      end

      describe 'Existing Warden authentication' do
        before do
          @resource = users(:second_confirmed_email_user)
          @resource.skip_confirmation!
          @resource.save!
          login_as( @resource, :scope => :user)

          # no auth headers sent, testing that warden authenticates correctly.
          get '/demo/members_only', {}, nil

          @resp_token       = response.headers['access-token']
          @resp_client_id   = response.headers['client']
          @resp_expiry      = response.headers['expiry']
        end

        describe 'devise mappings' do
          it 'should define current_user' do
            assert_equal @resource, @controller.current_user
          end

          it 'should define user_signed_in?' do
            assert @controller.user_signed_in?
          end

          it 'should not define current_mang' do
            refute_equal @resource, @controller.current_mang
          end


          it 'should increase the number of tokens by a factor of 2 up to 11' do
            @first_token = @resource.tokens.keys.first

            DeviseTokenAuth.max_number_of_devices = 11
            (1..10).each do |n|
              assert_equal [11, 2*n].min, @resource.reload.tokens.keys.length
              get '/demo/members_only', {}, nil
            end

            assert_not_includes @resource.reload.tokens.keys, @first_token
          end
        end

        it 'should return success status' do
          assert_equal 200, response.status
        end

        it 'should receive new token after successful request' do
          assert @resp_token
        end

        it 'should set the token expiry in the auth header' do
          assert @resp_expiry
        end

        it 'should return the client id in the auth header' do
          assert @resp_client_id
        end
      end

      describe 'existing Warden authentication with ignored token data' do
        before do
          @resource = users(:second_confirmed_email_user)
          @resource.skip_confirmation!
          @resource.save!
          login_as( @resource, :scope => :user)

          get '/demo/members_only', {}, @auth_headers

          @resp_token       = response.headers['access-token']
          @resp_client_id   = response.headers['client']
          @resp_expiry      = response.headers['expiry']
        end

        describe 'devise mappings' do
          it 'should define current_user' do
            assert_equal @resource, @controller.current_user
          end

          it 'should define user_signed_in?' do
            assert @controller.user_signed_in?
          end

          it 'should not define current_mang' do
            refute_equal @resource, @controller.current_mang
          end
        end

        it 'should return success status' do
          assert_equal 200, response.status
        end

        it 'should receive new token after successful request' do
          assert @resp_token
        end

        it 'should set the token expiry in the auth header' do
          assert @resp_expiry
        end

        it 'should return the client id in the auth header' do
          assert @resp_client_id
        end

        it "should not use the existing token's client" do
          refute_equal @auth_headers['client'], @resp_client_id
        end
      end

    end
  end
end
