#-------------------------------------------------------------------------------
# Copyright (c) 2015 Micorosft Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#-------------------------------------------------------------------------------

# Attribution:
# Most of this code is patched together from the following repositories:
#
# https://github.com/AzureAD/omniauth-azure-activedirectory/
# https://github.com/KonaTeam/omniauth-azure-oauth2

require 'jwt'
require 'omniauth/strategies/oauth2'
require 'openssl'
require 'securerandom'

module OmniAuth
  module Strategies
    # Main class for Azure OAuth2 strategy.
    class AzureOauth2 < OmniAuth::Strategies::OAuth2
      BASE_AZURE_URL = 'https://login.microsoftonline.com'
      BASE_SCOPES = %w[openid profile email].freeze

      option :name, 'azure_oauth2'
      option :tenant, 'common'
      option :client_id, nil
      option :client_secret, nil
      option :scope, BASE_SCOPES.join(' ')

      def client
        tenant = options.tenant
        options.client_options.authorize_url = "#{BASE_AZURE_URL}/#{tenant}/oauth2/v2.0/authorize"
        options.client_options.token_url = "#{BASE_AZURE_URL}/#{tenant}/oauth2/v2.0/token"

        super
      end

      uid { claims['sub'] }

      info do
        {
          name: claims['name'] || claims['oid'],
          email: claims['email'] || claims['preferred_username'],
          oid: claims['oid'],
          tid: claims['tid']
        }
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def authorize_params
        options.authorize_params[:nonce] = new_nonce

        super
      end

      def claims
        @id_token ||= access_token.params['id_token']
        @claims ||= validate_and_parse_id_token(@id_token)
      end

      private

      def validate_and_parse_id_token(id_token)
        jwt_claims =
          JWT.decode(id_token, nil, true, verify_options) do |header|
            # There should always be one key from the discovery endpoint that
            # matches the id in the JWT header.
            x5c = (signing_keys.find do |key|
              key['kid'] == header['kid']
            end || {})['x5c']
            if x5c.nil? || x5c.empty?
              raise JWT::VerificationError, 'No keys from key endpoint match the id token'
            end
            # The key also contains other fields, such as n and e, that are
            # redundant. x5c is sufficient to verify the id token.
            OpenSSL::X509::Certificate.new(JWT.base64url_decode(x5c.first)).public_key
          end

        claims = jwt_claims.first

        return claims if claims['nonce'] == read_nonce

        raise JWT::DecodeError, 'Returned nonce did not match.'
      end

      ##
      # The keys used to sign the id token JWTs. This is just a memoized version
      # of #fetch_signing_keys.
      #
      # @return Array[Hash]
      def signing_keys
        @signing_keys ||= fetch_signing_keys
      end

      ##
      # Fetches the current signing keys for Azure AD. Note that there should
      # always two available, and that they have a 6 week rollover.
      #
      # Each key is a hash with the following fields:
      #   kty, use, kid, x5t, n, e, x5c
      #
      # @return Array[Hash]
      def fetch_signing_keys
        response = JSON.parse(Net::HTTP.get(URI(signing_keys_url)))
        response['keys']
      rescue JSON::ParserError
        raise StandardError, 'Unable to fetch AzureAD signing keys.'
      end

      ##
      # The location of the public keys of the token signer. This is parsed from
      # the OpenId config response.
      #
      # @return String
      def signing_keys_url
        return openid_config['jwks_uri'] if openid_config.include? 'jwks_uri'
        raise StandardError, 'No jwks_uri in OpenId config response.'
      end

      #
      # A memoized version of #fetch_openid_config.
      #
      # @return Hash
      def openid_config
        @openid_config ||= fetch_openid_config
      end

      def fetch_openid_config
        JSON.parse(Net::HTTP.get(URI(openid_config_url)))
      rescue JSON::ParserError
        raise StandardError, 'Unable to fetch OpenId configuration for ' \
          'AzureAD tenant.'
      end

      def openid_config_url
        "https://login.microsoftonline.com/#{options.tenant}/v2.0/.well-known/openid-configuration/"
      end

      def new_nonce
        session['azure_oauth2.nonce'] = SecureRandom.uuid
      end

      def read_nonce
        session.delete 'azure_oauth2.nonce'
      end

      ##
      # The options passed to the Ruby JWT library to verify the id token.
      # Note that these are not all the checks we perform. Some (like nonce)
      # are not handled by the JWT API and are checked manually in
      # #validate_and_parse_id_token.
      #
      # https://github.com/jwt/ruby-jwt#support-for-reserved-claim-names
      #
      # @return Hash
      def verify_options
        { verify_expiration: true,
          verify_not_before: true,
          verify_iat: true,
          verify_iss: false,
          verify_aud: true,
          'aud' => client.id }
      end
    end
  end
end
