export type CredentialKind =
  | "password"
  | "api_token"
  | "ssh_key"
  | "ssh_password"
  | "database_connection"
  | "certificate"
  | "smtp_account"
  | "custom";

export type Environment =
  | "local"
  | "development"
  | "staging"
  | "production"
  | { custom: string };

export interface CredentialMeta {
  id: string;
  name: string;
  kind: CredentialKind;
  environment: Environment;
  tags: string[];
  created_at: string;
  updated_at: string;
  notes: string | null;
}

export interface VaultStatus {
  unlocked: boolean;
  credential_count: number;
  environments: string[];
}

export interface AuditEntry {
  timestamp: string;
  credential_id: string | null;
  credential_name: string | null;
  action: string;
  tool: string;
  success: boolean;
  details: string | null;
}

export interface PolicyRule {
  credential_id: string;
  allowed_tools: string[];
  http_url_patterns: string[];
  ssh_command_patterns: string[];
  sql_allow_write: boolean;
  smtp_allowed_recipients: string[];
  rate_limit: { max_requests: number; window_secs: number } | null;
}

// Secret types for the credential editor forms
export interface PasswordSecret {
  type: "password";
  username: string;
  password: string;
  url?: string;
}

export interface ApiTokenSecret {
  type: "api_token";
  token: string;
  header_name?: string;
  prefix?: string;
}

export interface SshKeySecret {
  type: "ssh_key";
  username: string;
  host: string;
  port: number;
  private_key: string;
  passphrase?: string;
}

export interface SshPasswordSecret {
  type: "ssh_password";
  username: string;
  host: string;
  port: number;
  password: string;
}

export interface DatabaseConnectionSecret {
  type: "database_connection";
  driver: "postgres" | "mysql" | "sqlite";
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  params?: Record<string, string>;
}

export interface CertificateSecret {
  type: "certificate";
  cert_pem: string;
  key_pem: string;
  ca_pem?: string;
}

export interface SmtpAccountSecret {
  type: "smtp_account";
  host: string;
  port: number;
  username: string;
  password: string;
  encryption: "none" | "start_tls" | "tls";
}

export interface CustomSecret {
  type: "custom";
  fields: Record<string, string>;
}

export type CredentialSecret =
  | PasswordSecret
  | ApiTokenSecret
  | SshKeySecret
  | SshPasswordSecret
  | DatabaseConnectionSecret
  | CertificateSecret
  | SmtpAccountSecret
  | CustomSecret;

export const CREDENTIAL_KINDS: { value: CredentialKind; label: string }[] = [
  { value: "password", label: "Password" },
  { value: "api_token", label: "API Token" },
  { value: "ssh_key", label: "SSH Key" },
  { value: "ssh_password", label: "SSH Password" },
  { value: "database_connection", label: "Database" },
  { value: "certificate", label: "Certificate" },
  { value: "smtp_account", label: "SMTP Account" },
  { value: "custom", label: "Custom" },
];

export const ENVIRONMENTS: string[] = [
  "local",
  "development",
  "staging",
  "production",
];

export function environmentToString(env: Environment): string {
  if (typeof env === "string") return env;
  return env.custom;
}

export function kindLabel(kind: CredentialKind): string {
  return CREDENTIAL_KINDS.find((k) => k.value === kind)?.label ?? kind;
}
