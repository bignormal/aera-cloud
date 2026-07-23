import { StrictMode, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { PageFrame, Card } from "./components/Layout";
import { I18nProvider, useI18n } from "./i18n";
import { AccountPage } from "./pages/AccountPage";
import { AuthorizePage } from "./pages/AuthorizePage";
import { DeleteAccountPage } from "./pages/DeleteAccountPage";
import { DevicesPage } from "./pages/DevicesPage";
import { ForgotPasswordPage } from "./pages/ForgotPasswordPage";
import { LoginPage } from "./pages/LoginPage";
import { RegisterPage } from "./pages/RegisterPage";
import { PublicConfigProvider } from "./public-config";
import { Link, RouterProvider, useRouter } from "./router";
import "./styles.css";

function Redirect({ to }: { to: string }) {
  const { navigate } = useRouter();
  useEffect(() => navigate(to, { replace: true }), [navigate, to]);
  return null;
}

function NotFound() {
  const { t } = useI18n();
  return (
    <PageFrame compact>
      <Card className="auth-card">
        <h1>{t("notFound")}</h1>
        <Link className="primary-link" href="/login">
          {t("backToLogin")}
        </Link>
      </Card>
    </PageFrame>
  );
}

function App() {
  const { location } = useRouter();
  switch (location.pathname) {
    case "/":
      return <Redirect to="/login" />;
    case "/login":
      return <LoginPage />;
    case "/register":
      return <RegisterPage />;
    case "/forgot-password":
      return <ForgotPasswordPage />;
    case "/authorize":
      return <AuthorizePage />;
    case "/account":
      return <AccountPage />;
    case "/devices":
      return <DevicesPage />;
    case "/delete-account":
      return <DeleteAccountPage />;
    default:
      return <NotFound />;
  }
}

const root = document.getElementById("root");
if (!root) throw new Error("AgentEra account center root is missing");
createRoot(root).render(
  <StrictMode>
    <I18nProvider>
      <PublicConfigProvider>
        <RouterProvider>
          <App />
        </RouterProvider>
      </PublicConfigProvider>
    </I18nProvider>
  </StrictMode>,
);
