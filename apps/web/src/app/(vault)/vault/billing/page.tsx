"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Badge, Banner, Button, Spinner, useNopassStore } from "@nopass/ui";
import type { BillingStatus, SubscriptionPlan } from "@nopass/types";
import { api } from "@/lib/api";
import { PageShell } from "@/components/vault/PageShell";

const PLAN_LABELS: Record<SubscriptionPlan, string> = {
  free: "Free",
  pro: "Pro",
  teams: "Teams",
  enterprise: "Enterprise",
};

const PLAN_DESCRIPTIONS: Record<SubscriptionPlan, string> = {
  free: "Unlimited vault items, sync, the Chrome extension, and team sharing for up to 3 members.",
  pro: "Everything in Free plus encrypted file attachments, hardware key 2FA, emergency access, and REST API access.",
  teams: "Everything in Pro plus unlimited org members, SSO / SAML, audit logs, and dedicated support.",
  enterprise: "Everything in Teams with custom contracts, SLAs, and on-premise options.",
};

function FeatureList({ items }: { items: string[] }) {
  return (
    <ul className="list-disc space-y-1 pl-4 text-meta text-muted marker:text-faint">
      {items.map((f) => (
        <li key={f}>{f}</li>
      ))}
    </ul>
  );
}

export default function BillingPage() {
  const router = useRouter();
  const { sessionToken } = useNopassStore();
  const [status, setStatus] = useState<BillingStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const proMonthlyPriceId = process.env.NEXT_PUBLIC_STRIPE_PRO_MONTHLY_PRICE_ID ?? "";
  const proAnnualPriceId = process.env.NEXT_PUBLIC_STRIPE_PRO_ANNUAL_PRICE_ID ?? "";
  const teamsPriceId = process.env.NEXT_PUBLIC_STRIPE_TEAMS_PRICE_ID ?? "";

  useEffect(() => {
    document.title = "Billing — nopwd";
  }, []);

  useEffect(() => {
    if (!sessionToken) {
      router.replace("/login");
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const data = await api.billing.status(sessionToken);
        if (!cancelled) setStatus(data);
      } catch {
        if (!cancelled) setError("Failed to load billing status");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [sessionToken, router]);

  const startCheckout = async (priceId: string) => {
    if (!sessionToken) return;
    setActionLoading(true);
    setError(null);
    try {
      const origin = window.location.origin;
      const { url } = await api.billing.checkout(
        {
          priceId,
          successUrl: `${origin}/vault/billing?session=success`,
          cancelUrl: `${origin}/vault/billing`,
        },
        sessionToken,
      );
      window.location.href = url;
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to start checkout");
      setActionLoading(false);
    }
  };

  const openPortal = async () => {
    if (!sessionToken) return;
    setActionLoading(true);
    setError(null);
    try {
      const { url } = await api.billing.portal({ returnUrl: window.location.href }, sessionToken);
      window.location.href = url;
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to open billing portal");
      setActionLoading(false);
    }
  };

  const plan = status?.plan ?? "free";
  const isActive = status?.status === "active" || status?.status === "trialing";
  const periodEnd = status?.currentPeriodEnd ? new Date(status.currentPeriodEnd).toLocaleDateString() : null;

  return (
    <PageShell title="Billing" description="Your plan and payment details.">
      {loading ? (
        <div className="flex items-center gap-2 py-8 text-ui text-muted" role="status">
          <Spinner /> Loading billing status…
        </div>
      ) : (
        <>
          {error && (
            <Banner tone="danger" className="mb-4">
              {error}
            </Banner>
          )}

          <section aria-labelledby="current-plan" className="mb-8 rounded-lg border border-divider bg-surface p-5">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-meta text-muted">Current plan</p>
                <div className="mt-1 flex items-center gap-2">
                  <h2 id="current-plan" className="text-h2 font-semibold text-fg">
                    {PLAN_LABELS[plan]}
                  </h2>
                  {isActive && plan !== "free" && <Badge tone="success">Active</Badge>}
                </div>
              </div>
              {plan !== "free" && isActive && (
                <Button onClick={openPortal} pending={actionLoading} pendingLabel="Opening…">
                  Manage billing
                </Button>
              )}
            </div>
            <p className="mt-3 max-w-prose text-ui text-muted">{PLAN_DESCRIPTIONS[plan]}</p>
            {periodEnd && (
              <p className="mt-3 text-meta text-muted">
                {status?.status === "canceled" ? "Access until" : "Renews"}: <span className="tabular-nums">{periodEnd}</span>
              </p>
            )}
          </section>

          {plan === "free" && (
            <section aria-labelledby="upgrade">
              <h2 id="upgrade" className="mb-3 text-h2 font-semibold text-fg">
                Upgrade
              </h2>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="flex flex-col rounded-lg border border-divider bg-surface p-5">
                  <h3 className="text-h3 font-semibold text-fg">Pro</h3>
                  <p className="mt-2">
                    <span className="text-h1 font-semibold tabular-nums text-fg">€4</span>
                    <span className="text-ui text-muted"> / month</span>
                  </p>
                  <p className="mb-4 text-meta text-muted">or €36 / year (save 25%)</p>
                  <FeatureList items={["File attachments (1 GB)", "Hardware key 2FA", "Emergency access", "REST API access"]} />
                  <div className="mt-5 flex flex-col gap-2">
                    {proMonthlyPriceId && (
                      <Button variant="primary" onClick={() => startCheckout(proMonthlyPriceId)} pending={actionLoading} pendingLabel="Loading…">
                        Subscribe monthly
                      </Button>
                    )}
                    {proAnnualPriceId && (
                      <Button onClick={() => startCheckout(proAnnualPriceId)} pending={actionLoading} pendingLabel="Loading…">
                        Subscribe yearly — €36
                      </Button>
                    )}
                    {!proMonthlyPriceId && !proAnnualPriceId && (
                      <p className="text-meta text-muted">Coming soon</p>
                    )}
                  </div>
                </div>

                <div className="flex flex-col rounded-lg border border-divider bg-surface p-5">
                  <h3 className="text-h3 font-semibold text-fg">Teams</h3>
                  <p className="mt-2">
                    <span className="text-h1 font-semibold tabular-nums text-fg">€5</span>
                    <span className="text-ui text-muted"> / user / month</span>
                  </p>
                  <p className="mb-4 text-meta text-muted">Minimum 3 seats, billed annually</p>
                  <FeatureList items={["Everything in Pro", "Unlimited org members", "SSO / SAML", "Audit logs"]} />
                  <div className="mt-5 flex flex-col gap-2">
                    {teamsPriceId ? (
                      <Button onClick={() => startCheckout(teamsPriceId)} pending={actionLoading} pendingLabel="Loading…">
                        Start Teams trial
                      </Button>
                    ) : (
                      <p className="text-meta text-muted">Coming soon</p>
                    )}
                  </div>
                </div>
              </div>
            </section>
          )}

          {plan !== "free" && (
            <Button variant="ghost" onClick={openPortal} disabled={actionLoading}>
              Cancel subscription or change plan
            </Button>
          )}
        </>
      )}
    </PageShell>
  );
}
