Rails.application.routes.draw do
  post  :webhook,   to: 'webhook#handle_webhook'
end
