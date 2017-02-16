module DeviseTokenAuth
  class TokenValidationsController < DeviseTokenAuth::ApplicationController
    skip_before_action :assert_is_devise_resource!, :only => [:refresh_token, :validate_token]
    before_action :set_refresh_token_header, :only => [:refresh_token]
    before_action :set_user_by_token, :only => [:refresh_token, :validate_token]

    def refresh_token
      # @resource will have been set by set_user_token concern
      if @resource
        @resource.create_new_auth_token(request.headers[DeviseTokenAuth.headers_names[:'client']])

        yield @resource if block_given?
        render_validate_token_success
      else
        render_validate_token_error
      end
    end

    def validate_token
      # @resource will have been set by set_user_token concern
      if @resource
        yield @resource if block_given?
        render_validate_token_success
      else
        render_validate_token_error
      end
    end

    protected

    def render_validate_token_success
      render json: {
        success: true,
        data: resource_data(resource_json: @resource.token_validation_response)
      }
    end

    def render_validate_token_error
      render json: {
        success: false,
        errors: [I18n.t("devise_token_auth.token_validations.invalid")]
      }, status: 401
    end

    private
    def set_refresh_token_header
      request.headers[:refresh_token] = true
    end

  end
end
