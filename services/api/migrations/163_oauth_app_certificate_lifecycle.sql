-- 163: lifecycle of an AiSOC-generated OAuth app certificate.
--
-- AiSOC can now generate the Entra app certificate itself and roll it before
-- it expires (Microsoft Graph addKey/removeKey, the ms_cert_rotation worker).
-- Only certificates AiSOC generated are rotated; a pasted one is only warned
-- about.
--
--   client_certificate_not_after  certificate expiry (NULL: unknown, e.g. a
--                                 key-only PEM with a thumbprint)
--   client_certificate_managed    true when AiSOC generated it and owns rotation
--   client_certificate_rotation   non-secret rotation state: Entra keyId of the
--                                 current cert, application object id, Entra
--                                 tenant for the token request, last error /
--                                 warning and attempt time
ALTER TABLE oauth_app_credentials
    ADD COLUMN IF NOT EXISTS client_certificate_not_after TIMESTAMPTZ;

ALTER TABLE oauth_app_credentials
    ADD COLUMN IF NOT EXISTS client_certificate_managed BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE oauth_app_credentials
    ADD COLUMN IF NOT EXISTS client_certificate_rotation JSONB NOT NULL DEFAULT '{}'::jsonb;
