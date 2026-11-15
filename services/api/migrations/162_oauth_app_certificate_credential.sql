-- 162: OAuth app certificate credential (Microsoft identity platform).
--
-- The hosted one-click OAuth flow authenticated its token exchanges with a
-- client secret only. Entra ID also accepts an app certificate: the API
-- signs an RS256 client_assertion (RFC 7523) with the certificate's private
-- key instead of sending client_secret. A tenant registers exactly one of the
-- two; the certificate wins if both were ever present.
--
--   client_certificate_vault       vault:v1 ciphertext of the PEM (private
--                                  key, optionally followed by the cert).
--                                  Never returned over the wire.
--   client_certificate_thumbprint  hex SHA-1 thumbprint (x5t), derived from
--                                  the cert when the PEM carries one.
ALTER TABLE oauth_app_credentials
    ALTER COLUMN client_secret_vault DROP NOT NULL;

ALTER TABLE oauth_app_credentials
    ADD COLUMN IF NOT EXISTS client_certificate_vault TEXT;

ALTER TABLE oauth_app_credentials
    ADD COLUMN IF NOT EXISTS client_certificate_thumbprint TEXT;

ALTER TABLE oauth_app_credentials
    DROP CONSTRAINT IF EXISTS oauth_app_credentials_secret_or_cert_check;

ALTER TABLE oauth_app_credentials
    ADD CONSTRAINT oauth_app_credentials_secret_or_cert_check
    CHECK (client_secret_vault IS NOT NULL OR client_certificate_vault IS NOT NULL);
