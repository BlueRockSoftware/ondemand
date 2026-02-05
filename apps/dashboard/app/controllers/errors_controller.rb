# The controller for error responses.
class ErrorsController < ApplicationController
  # https://mattbrictson.com/dynamic-rails-error-pages
  #
  # to test in development, comment out this line in
  # config/environments/devleopment.rb:
  #
  #     config.consider_all_requests_local       = true
  #
  # the routes.rb is set to the app to handle exceptions in application.rb
  #
  def not_found
    respond_to do |format|
      format.html { render status: :not_found }
      format.json { render nothing: true, status: :not_found }
    end
  end

  def internal_server_error
    @exception  = request.env['action_dispatch.exception']

    # FIXME: a better solution exists than this
    # avoid rendering nav in case those introduce exceptions
    @hidenav = true

    #TODO: log exception information you want to log here
    # after removing it from the normal logging via lograge

    # When exceptions_app runs, request.path is /500 so we can't use path. Use Accept
    # to return JSON with the exception message for API callers (e.g. Admin API via
    # Internal API), so they can surface the real error instead of generic 500.
    if request.format.json? || request.accepts.any? { |mime| mime.to_s == 'application/json' }
      msg = @exception.respond_to?(:message) ? @exception.message : 'Internal server error'
      render json: { status: 'error', code: 'INTERNAL_ERROR', message: msg }, status: :internal_server_error
      return
    end

    respond_to do |format|
      format.html { render status: :internal_server_error }
      format.json { head :internal_server_error }
    end
  end
end
