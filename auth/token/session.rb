# more information about JWT token - https://github.com/jwt/ruby-jwt

module Auth
  module Token
    class Session
      SESSION_AUD_CLAIM = 'session'
      DEFAULT_EXPIRATION_TIME = 1.year # token will be valid for 1 year
      JWT_KEY = Rails.application.credentials.jwt_key! # some unique token

      class << self
        def generate(model, expiration_time = DEFAULT_EXPIRATION_TIME)
          payload = {
            aud: SESSION_AUD_CLAIM,
            sub: model.id,
            exp: (DateTime.current + expiration_time).to_i,
            iat: DateTime.current.to_i
          }

          JWT.encode(payload, JWT_KEY)
        end

        def model_by_token(token)
          token = JWT.decode(token, JWT_KEY, true, aud: SESSION_AUD_CLAIM, verify_aud: true)
          model_id = token[0]['sub']
          token_issued_at = token[0]['iat']
          model = Account.find_by(id: model_id)

          return unless model

          # after reset or update password jwt token becomes invalid so we check if token is valid
          token_actual?(model, token_issued_at) ? model : nil
        rescue JWT::VerificationError, JWT::DecodeError, NameError
          nil
        end

        private

        def token_actual?(model, token_issued_at)
          return true if !model.email? || model.password_reset_at.nil?

          model.password_reset_at.to_i < token_issued_at
        end
      end
    end
  end
end

# in your Gemfile add   gem 'jwt'

# --examples--
# token = Auth::Token::Session.generate(User.first, 1.month) - it returns some token
# user = Auth::Token::Session.model_by_token(token ) - it returns user object
