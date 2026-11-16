"use client";

/**
 * "Generate certificate" for Entra app-certificate credentials.
 *
 * The API makes the key pair and a self-signed certificate, keeps the private
 * key (vault-encrypted, parked for 24 h under a pending id) and returns only
 * the public certificate. The operator downloads the `.cer`, uploads it to the
 * app registration, and the form's save call hands the pending id back so the
 * API moves the key into the connector / OAuth app. Pasting your own PEM stays
 * available as the alternative; only generated certificates auto-rotate.
 */

import { useState } from "react";
import toast from "react-hot-toast";
import {
  connectorsApi,
  saveBlob,
  type CertificateLifecycle,
  type GeneratedCertificate,
} from "@/lib/api";
import { describeApiError } from "./AddConnectorModal";

export const ENTRA_UPLOAD_HINT =
  "Upload this .cer in Entra admin center → App registrations → your app → Certificates & secrets → Certificates";

export function formatExpiry(iso: string | null | undefined): string {
  if (!iso) return "unknown";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "unknown" : d.toISOString().slice(0, 10);
}

function derBlob(base64: string): Blob {
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  return new Blob([bytes], { type: "application/pkix-cert" });
}

const inputClass =
  "w-full rounded-lg border border-surface-border bg-surface-card px-3 py-2 text-sm text-fg-primary placeholder:text-fg-subtle focus:outline-none focus:ring-1 focus:ring-blue-500/40 font-mono";

interface CertificateGeneratorProps {
  connectorType: string;
  /** Instance / app label, used in the certificate's CN. */
  name?: string;
  /** Entra tenant id from the surrounding form; when undefined an input is shown. */
  entraTenantId?: string;
  generated: GeneratedCertificate | null;
  onGenerated: (cert: GeneratedCertificate | null) => void;
}

export function CertificateGenerator({
  connectorType,
  name,
  entraTenantId,
  generated,
  onGenerated,
}: CertificateGeneratorProps) {
  const [busy, setBusy] = useState(false);
  const [objectId, setObjectId] = useState("");
  const [tenant, setTenant] = useState("");
  const askTenant = entraTenantId === undefined;
  // Rotation signs in to the app's own tenant; without it a generated cert can't auto-rotate.
  // Same rule as the API's valid_tenant(): a GUID or verified domain, not a multi-tenant alias.
  const tenantValue = tenant.trim();
  const tenantMissing =
    askTenant &&
    (!/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/.test(tenantValue) ||
      ["common", "organizations", "consumers"].includes(tenantValue.toLowerCase()));

  const generate = async () => {
    setBusy(true);
    try {
      const cert = await connectorsApi.generateCertificate({
        connector_type: connectorType,
        name: name?.trim() || null,
        entra_directory_id: (askTenant ? tenant : entraTenantId)?.trim() || null,
        application_object_id: objectId.trim() || null,
      });
      onGenerated(cert);
    } catch (err) {
      toast.error(describeApiError(err, "Could not generate a certificate"));
    } finally {
      setBusy(false);
    }
  };

  if (generated) {
    return (
      <div
        className="space-y-2 rounded-lg border border-surface-border bg-surface-card p-3 text-xs"
        data-testid="generated-certificate"
      >
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-fg-secondary">
          <span>
            Thumbprint <code className="font-mono text-fg-primary">{generated.thumbprint}</code>
          </span>
          <span>expires {formatExpiry(generated.not_after)}</span>
        </div>
        <p className="text-fg-secondary leading-relaxed">{ENTRA_UPLOAD_HINT}</p>
        <p className="text-fg-muted leading-relaxed">
          The private key stays in AiSOC and is saved with this form; AiSOC rotates the certificate
          automatically 30 days before it expires.
        </p>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() =>
              saveBlob(derBlob(generated.certificate_der_base64), `aisoc-${connectorType}.cer`)
            }
            className="rounded-md bg-blue-600 px-3 py-1.5 font-semibold text-white hover:bg-blue-500"
          >
            Download .cer
          </button>
          <button
            type="button"
            onClick={() => onGenerated(null)}
            className="rounded-md border border-surface-border px-3 py-1.5 text-fg-secondary hover:bg-surface-hover"
          >
            Discard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-2 rounded-lg border border-dashed border-surface-border p-3 text-xs">
      <p className="text-fg-secondary leading-relaxed">
        No certificate yet? Let AiSOC generate one (RSA-2048, valid 2 years, rotated automatically).
      </p>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {askTenant && (
          <input
            aria-label="Entra tenant ID"
            value={tenant}
            onChange={(e) => setTenant(e.target.value)}
            placeholder="Entra tenant ID (required for auto-rotation)"
            className={inputClass}
          />
        )}
        <input
          aria-label="Application object ID (optional)"
          value={objectId}
          onChange={(e) => setObjectId(e.target.value)}
          placeholder="Application object ID (optional)"
          className={inputClass}
        />
      </div>
      <p className="text-fg-muted leading-relaxed">
        The Object ID is on the app&apos;s Overview page. With it, rotation needs no directory-read
        permission.
      </p>
      <button
        type="button"
        onClick={generate}
        disabled={busy || tenantMissing}
        className="rounded-md bg-blue-600 px-3 py-1.5 font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
      >
        {busy ? "Generating…" : "Generate certificate"}
      </button>
    </div>
  );
}

/** "Certificate expires <date> · auto-rotates" / "— rotate manually" for a saved credential. */
export function CertificateStatus({
  lifecycle,
  onDownload,
}: {
  lifecycle: CertificateLifecycle | null | undefined;
  onDownload?: () => Promise<void>;
}) {
  if (!lifecycle || (!lifecycle.not_after && !lifecycle.managed)) return null;
  const download = async () => {
    try {
      await onDownload?.();
    } catch (err) {
      toast.error(describeApiError(err, "Could not download the certificate"));
    }
  };
  return (
    <div className="space-y-1 text-xs" data-testid="certificate-status">
      <p className="text-fg-secondary">
        Certificate expires {formatExpiry(lifecycle.not_after)}
        {lifecycle.managed ? " · auto-rotates" : " — rotate manually"}
        {onDownload && (
          <>
            {" · "}
            <button
              type="button"
              onClick={download}
              className="text-blue-600 underline-offset-2 hover:underline"
            >
              Download .cer
            </button>
          </>
        )}
      </p>
      {lifecycle.last_error && (
        <p className="text-red-600">Last auto-rotation failed: {lifecycle.last_error}</p>
      )}
      {lifecycle.last_warning && <p className="text-amber-600">{lifecycle.last_warning}</p>}
    </div>
  );
}
