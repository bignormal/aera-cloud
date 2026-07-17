import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type AnchorHTMLAttributes,
  type MouseEvent,
  type ReactNode,
} from "react";

export interface AppLocation {
  pathname: string;
  search: string;
}

interface RouterValue {
  location: AppLocation;
  navigate: (target: string, options?: { replace?: boolean }) => void;
}

const RouterContext = createContext<RouterValue | null>(null);

function currentLocation(): AppLocation {
  return { pathname: window.location.pathname, search: window.location.search };
}

export function isSafeInternalTarget(target: string): boolean {
  if (!target.startsWith("/") || target.startsWith("//") || target.includes("\n") || target.includes("\r")) {
    return false;
  }
  const parsed = new URL(target, window.location.origin);
  return parsed.origin === window.location.origin;
}

export function RouterProvider({ children }: { children: ReactNode }) {
  const [location, setLocation] = useState(currentLocation);
  useEffect(() => {
    const update = () => setLocation(currentLocation());
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, []);
  const navigate = useCallback((target: string, options?: { replace?: boolean }) => {
    if (!isSafeInternalTarget(target)) {
      return;
    }
    if (options?.replace) {
      window.history.replaceState(null, "", target);
    } else {
      window.history.pushState(null, "", target);
    }
    setLocation(currentLocation());
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
  }, []);
  const value = useMemo(() => ({ location, navigate }), [location, navigate]);
  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
}

export function useRouter(): RouterValue {
  const value = useContext(RouterContext);
  if (!value) {
    throw new Error("RouterProvider is required");
  }
  return value;
}

export function Link({ href, onClick, ...props }: AnchorHTMLAttributes<HTMLAnchorElement>) {
  const { navigate } = useRouter();
  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event);
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || !href) {
      return;
    }
    if (isSafeInternalTarget(href)) {
      event.preventDefault();
      navigate(href);
    }
  };
  return <a {...props} href={href} onClick={handleClick} />;
}
