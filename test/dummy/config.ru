# This file is used by Rack-based servers to start the application.

require ::File.expand_path('../config/environment',  __FILE__)
run Rails.application

# allow cross origin requests
require 'rack/cors'
use Rack::Cors do
  allow do
    origins '*'
    resource '*',
      :headers => :any,
      :expose => ['Authorization', 'client'],
      :methods => [:get, :post, :options, :delete, :put]
  end
end
