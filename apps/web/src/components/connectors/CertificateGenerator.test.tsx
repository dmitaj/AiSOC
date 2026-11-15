/**
 * "Generate certificate": the API makes the key, the browser only ever sees
 * the public certificate and a pending id, and the save call hands that id
 * back instead of a PEM.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type {
  ConnectorCatalogEntry,
  ConnectorSchemaField,
  GeneratedCertificate,
  OAuthAppView,
} from "@/lib/api";

const api = vi.hoisted(() => ({
  catalog: vi.fn(),
  create: vi.fn(),
  generateCertificate: vi.fn(),
  upsertApp: vi.fn(),
  lastEvent: vi.fn(),
  update: vi.fn(),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    connectorsApi: {
      ...actual.connectorsApi,
      catalog: api.catalog,
      create: api.create,
      generateCertificate: api.generateCertificate,
      lastEvent: api.lastEvent,
      update: api.update,
    },
    oauthApi: { ...actual.oauthApi, upsertApp: api.upsertApp },
  };
});

const toastMock = vi.hoisted(() => Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }));
vi.mock("react-hot-toast", () => ({ __esModule: true, default: toastMock }));

import { AddConnectorModal, OAuthAppRegistrationForm } from "./AddConnectorModal";
import { CertificateStatus, ENTRA_UPLOAD_HINT } from "./CertificateGenerator";
import { EditConnectorModal } from "./EditConnectorModal";

const FIELDS: ConnectorSchemaField[] = [
  { name: "tenant_id", type: "string", label: "Tenant ID", required: true },
  { name: "client_id", type: "string", label: "Application (Client) ID", required: true },
  { name: "client_secret", type: "secret", label: "Client Secret", required: false },
  {
    name: "certificate_pem",
    type: "secret",
    label: "Certificate PEM (private key)",
    required: false,
  },
  {
    name: "certificate_thumbprint",
    type: "string",
    label: "Certificate Thumbprint",
    required: false,
  },
  { name: "private_key_password", type: "secret", label: "Private Key Password", required: false },
];

const ENTRY = {
  connector_id: "azure_entra",
  connector_name: "Microsoft Entra ID",
  category: "iam",
  description: "Entra",
  fields: FIELDS,
} as ConnectorCatalogEntry;

const GENERATED: GeneratedCertificate = {
  pending_certificate_id: "pending-abc123",
  thumbprint: "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
  not_after: "2028-11-14T12:00:00+00:00",
  certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
  certificate_der_base64: btoa("der-bytes"),
  pending_expires_in_seconds: 86400,
};

beforeEach(() => {
  api.catalog.mockResolvedValue({ connectors: [ENTRY] });
  api.generateCertificate.mockResolvedValue(GENERATED);
  api.create.mockImplementation(async (body: { name: string }) => ({
    id: "c1",
    name: body.name,
    type: "azure_entra",
  }));
  api.lastEvent.mockResolvedValue({ data_flowing: false });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("Add connector: Generate certificate", () => {
  it("generates on the server, shows public info, downloads the .cer and saves the pending id", async () => {
    render(<AddConnectorModal open onClose={() => {}} primedConnectorId="azure_entra" />);
    // The wizard's labels are not wired with htmlFor; find inputs by order.
    const textInputs = await screen.findAllByRole("textbox");
    // [instance name, tenant_id, client_id, thumbprint, object id]
    fireEvent.change(textInputs[1], { target: { value: "11111111-2222-3333-4444-555555555555" } });
    fireEvent.change(textInputs[2], { target: { value: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" } });
    fireEvent.change(screen.getByLabelText("Application object ID (optional)"), {
      target: { value: "99999999-8888-7777-6666-555555555555" },
    });

    fireEvent.click(screen.getByRole("button", { name: "Generate certificate" }));
    await screen.findByTestId("generated-certificate");
    expect(api.generateCertificate).toHaveBeenCalledWith({
      connector_type: "azure_entra",
      name: "Microsoft Entra ID",
      entra_directory_id: "11111111-2222-3333-4444-555555555555",
      application_object_id: "99999999-8888-7777-6666-555555555555",
    });
    expect(screen.getByText(GENERATED.thumbprint)).toBeTruthy();
    expect(screen.getByText("expires 2028-11-14")).toBeTruthy();
    expect(screen.getByText(ENTRA_UPLOAD_HINT)).toBeTruthy();
    // The paste-your-own fields step aside.
    expect(screen.queryByText("Certificate Thumbprint")).toBeNull();
    expect(screen.queryByText("Private Key Password")).toBeNull();

    const createUrl = vi.fn(() => "blob:cer");
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: createUrl, revokeObjectURL: revoke });
    fireEvent.click(screen.getByRole("button", { name: "Download .cer" }));
    expect(createUrl).toHaveBeenCalledTimes(1);
    const blob = (createUrl.mock.calls[0] as unknown as [Blob])[0];
    expect(blob.type).toBe("application/pkix-cert");
    expect(await blob.text()).toBe("der-bytes");

    fireEvent.click(screen.getByRole("button", { name: "Save connector" }));
    await waitFor(() => expect(api.create).toHaveBeenCalled());
    const body = api.create.mock.calls[0][0];
    expect(body.auth_config).toEqual({ certificate_pending_id: "pending-abc123" });
    expect(JSON.stringify(body)).not.toContain("PRIVATE KEY");
  });

  it("keeps pasting a PEM as the alternative", async () => {
    render(<AddConnectorModal open onClose={() => {}} primedConnectorId="azure_entra" />);
    await screen.findByRole("button", { name: "Generate certificate" });
    expect(screen.getByText("Certificate PEM (private key)")).toBeTruthy();
    expect(screen.getByText("Certificate Thumbprint")).toBeTruthy();
  });

  it("Discard returns to the paste form and sends no pending id", async () => {
    render(<AddConnectorModal open onClose={() => {}} primedConnectorId="azure_entra" />);
    fireEvent.click(await screen.findByRole("button", { name: "Generate certificate" }));
    await screen.findByTestId("generated-certificate");
    fireEvent.click(screen.getByRole("button", { name: "Discard" }));
    expect(screen.getByText("Certificate Thumbprint")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Save connector" }));
    await waitFor(() => expect(api.create).toHaveBeenCalled());
    expect(api.create.mock.calls[0][0].auth_config).not.toHaveProperty("certificate_pending_id");
  });
});

describe("OAuth app form: Generate certificate", () => {
  it("registers the app with certificate_pending_id instead of a PEM", async () => {
    api.upsertApp.mockResolvedValue({} as OAuthAppView);
    const entry = {
      connector_id: "azure_entra",
      connector_name: "Microsoft Entra ID",
      oauth: {
        supported_in_hosted: true,
        token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        authorize_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        scopes: [],
      },
    } as unknown as ConnectorCatalogEntry;
    render(
      <OAuthAppRegistrationForm
        entry={entry}
        existing={null}
        schemaHints={entry.oauth}
        onSaved={() => {}}
      />
    );
    fireEvent.change(screen.getByPlaceholderText("client_xxxxxxxx"), { target: { value: "cid" } });
    fireEvent.click(screen.getByRole("radio", { name: "Certificate" }));
    fireEvent.change(screen.getByLabelText("Entra tenant ID"), {
      target: { value: "contoso.onmicrosoft.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Generate certificate" }));
    await screen.findByTestId("generated-certificate");
    expect(api.generateCertificate.mock.calls[0][0].entra_directory_id).toBe(
      "contoso.onmicrosoft.com"
    );
    expect(screen.queryByLabelText(/Certificate PEM/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Register OAuth app" }));
    await waitFor(() => expect(api.upsertApp).toHaveBeenCalled());
    const payload = api.upsertApp.mock.calls[0][1];
    expect(payload.certificate_pending_id).toBe("pending-abc123");
    expect(payload).not.toHaveProperty("certificate_pem");
    expect(payload).not.toHaveProperty("client_secret");
  });
});

describe("Edit connector: Generate certificate", () => {
  it("shows the stored expiry and saves only the pending id", async () => {
    api.update.mockImplementation(async (id: string) => ({
      id,
      name: "Entra",
      type: "azure_entra",
    }));
    const connector = {
      id: "c1",
      name: "Entra",
      type: "azure_entra",
      status: "active",
      config: {
        tenant_id: "11111111-2222-3333-4444-555555555555",
        client_id: "cid",
        certificate_lifecycle: { managed: false, not_after: "2027-01-02T00:00:00Z" },
      },
    } as never;
    render(<EditConnectorModal connector={connector} onClose={() => {}} />);
    const status = await screen.findByTestId("certificate-status");
    expect(status.textContent).toContain("expires 2027-01-02 — rotate manually");
    fireEvent.click(screen.getByRole("button", { name: "Generate certificate" }));
    await screen.findByTestId("generated-certificate");
    expect(api.generateCertificate.mock.calls[0][0].entra_directory_id).toBe(
      "11111111-2222-3333-4444-555555555555"
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(api.update).toHaveBeenCalled());
    expect(api.update.mock.calls[0][1]).toEqual({
      auth_config: { certificate_pending_id: "pending-abc123" },
    });
  });
});

describe("CertificateStatus", () => {
  it("says auto-rotates for a generated certificate", () => {
    render(<CertificateStatus lifecycle={{ managed: true, not_after: "2028-11-14T00:00:00Z" }} />);
    expect(screen.getByTestId("certificate-status").textContent).toContain(
      "Certificate expires 2028-11-14 · auto-rotates"
    );
  });

  it("says rotate manually for a pasted certificate, and shows a rotation failure", () => {
    render(
      <CertificateStatus
        lifecycle={{
          managed: false,
          not_after: "2027-01-02T00:00:00Z",
          last_error: "addKey failed: HTTP 403",
        }}
      />
    );
    const text = screen.getByTestId("certificate-status").textContent ?? "";
    expect(text).toContain("expires 2027-01-02 — rotate manually");
    expect(text).toContain("Last auto-rotation failed: addKey failed: HTTP 403");
  });
});
