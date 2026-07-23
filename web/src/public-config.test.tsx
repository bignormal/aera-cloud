import { render, screen } from "@testing-library/react";
import { PublicConfigProvider, usePublicConfig } from "./public-config";

function Probe() {
  const { config, error, loading } = usePublicConfig();
  if (loading) return <span>loading</span>;
  if (error || !config) return <span>closed</span>;
  return (
    <span>{`${config.environment}:${config.registration_mode}:${config.identity_verification_available}`}</span>
  );
}

test("loads the bounded public capability document once and exposes it to descendants", async () => {
  const fetchMock = vi.spyOn(window, "fetch").mockResolvedValue(
    new Response(
      JSON.stringify({
        environment: "internal_beta",
        public_registration_enabled: true,
        registration_mode: "direct",
        registration_identity_kinds: ["email"],
        identity_verification_available: false,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ),
  );

  render(
    <PublicConfigProvider>
      <Probe />
    </PublicConfigProvider>,
  );

  expect(screen.getByText("loading")).toBeVisible();
  expect(await screen.findByText("internal_beta:direct:false")).toBeVisible();
  expect(fetchMock).toHaveBeenCalledOnce();
  expect(fetchMock).toHaveBeenCalledWith(
    "/api/v1/public/config",
    expect.objectContaining({ credentials: "same-origin" }),
  );
});

test("fails closed when the public capability document cannot be loaded", async () => {
  vi.spyOn(window, "fetch").mockRejectedValue(new Error("offline"));

  render(
    <PublicConfigProvider>
      <Probe />
    </PublicConfigProvider>,
  );

  expect(await screen.findByText("closed")).toBeVisible();
  expect(screen.queryByText(/:true$/)).not.toBeInTheDocument();
});
