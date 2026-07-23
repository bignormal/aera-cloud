import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  getPublicConfig,
  type IdentityKind,
  type PublicConfig,
} from "./api/client";

interface PublicConfigState {
  config: PublicConfig | null;
  error: boolean;
  loading: boolean;
}

const PublicConfigContext = createContext<PublicConfigState | null>(null);

export function PublicConfigProvider({ children }: { children: ReactNode }) {
  const [config, setConfig] = useState<PublicConfig | null>(null);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    getPublicConfig()
      .then((candidate) => {
        if (!isPublicConfig(candidate)) {
          throw new Error("invalid public configuration");
        }
        if (active) {
          setConfig(candidate);
          setError(false);
        }
      })
      .catch(() => {
        if (active) {
          setConfig(null);
          setError(true);
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const value = useMemo(
    () => ({ config, error, loading }),
    [config, error, loading],
  );
  return (
    <PublicConfigContext.Provider value={value}>
      {children}
    </PublicConfigContext.Provider>
  );
}

export function usePublicConfig(): PublicConfigState {
  const value = useContext(PublicConfigContext);
  if (!value) {
    throw new Error("PublicConfigProvider is required");
  }
  return value;
}

function isPublicConfig(value: PublicConfig): boolean {
  const environments = new Set([
    "development",
    "test",
    "internal_beta",
    "production",
  ]);
  const modes = new Set(["verified", "direct"]);
  if (
    !value ||
    !environments.has(value.environment) ||
    !modes.has(value.registration_mode) ||
    typeof value.public_registration_enabled !== "boolean" ||
    typeof value.identity_verification_available !== "boolean" ||
    !Array.isArray(value.registration_identity_kinds) ||
    value.registration_identity_kinds.length === 0
  ) {
    return false;
  }
  const kinds = value.registration_identity_kinds as unknown[];
  if (
    !kinds.every(
      (kind): kind is IdentityKind => kind === "email" || kind === "phone",
    )
  ) {
    return false;
  }
  if (
    value.registration_mode === "direct" &&
    (value.environment !== "internal_beta" ||
      value.identity_verification_available ||
      kinds.length !== 1 ||
      kinds[0] !== "email")
  ) {
    return false;
  }
  return (
    value.registration_mode !== "verified" ||
    value.identity_verification_available
  );
}
