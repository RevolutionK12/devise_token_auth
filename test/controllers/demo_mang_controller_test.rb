require 'test_helper'

#  was the web request successful?
#  was the user redirected to the right page?
#  was the user successfully authenticated?
#  was the correct object stored in the response?
#  was the appropriate message delivered in the json payload?

class DemoMangControllerTest < ActionDispatch::IntegrationTest
  describe DemoMangController do
    describe "Token access" do
      before do
        @resource = mangs(:confirmed_email_user)
        @resource.skip_confirmation!
        @resource.save!

        @auth_headers = @resource.create_new_auth_token

        @token     = @auth_headers['Authorization']
        @client_id = @auth_headers['client']
      end

      describe 'successful request' do
        before do
          # ensure that request is not treated as batch request
          age_token(@resource, @client_id)

          get '/demo/members_only_mang', {}, @auth_headers

          @resp_token       = response.headers['Authorization']
          @resp_client_id   = response.headers['client']
        end

        describe 'devise mappings' do
          it 'should define current_mang' do
            assert_equal @resource, @controller.current_mang
          end

          it 'should define mang_signed_in?' do
            assert @controller.mang_signed_in?
          end

          it 'should not define current_user' do
            refute_equal @resource, @controller.current_user
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

        describe 'subsequent requests' do
          before do
            @resource.reload
            # ensure that request is not treated as batch request
            age_token(@resource, @client_id)

            get '/demo/members_only_mang', {}, @auth_headers.merge({'Authorization' => @resp_token})
          end

          it "should allow a new request to be made using new token" do
            assert_equal 200, response.status
          end
        end
      end

      describe 'failed request' do
        before do
          get '/demo/members_only_mang', {}, @auth_headers.merge({'Authorization' => "bogus"})
        end

        it 'should not return any auth headers' do
          refute response.headers['Authorization']
        end

        it 'should return error: unauthorized status' do
          assert_equal 401, response.status
        end
      end
    end
  end
end

