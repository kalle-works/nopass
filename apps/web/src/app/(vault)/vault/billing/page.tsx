"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useNopassStore } from "@nopass/ui";
import type { BillingStatus, SubscriptionPlan } from "@nopass/types";
import { api } from "@/lib/api";

const PLAN_LABELS: Record<SubscriptionPlan, string> = {
  free: "Free",
  pro: "Pro",
  teams: "Teams",
  enterprise: "Enterprise",
};

const PLAN_DESCRIPTIONS: Record<SubscriptionPlan, string> = {
  free: "Unlimited vault items, sync, browser extensions, and team sharing for up to 3 members.",
  pro: "Everything in Free plus encrypted file attachments, hardware key 2FA, emergency access, and REST API access.",
  teams: "Everything in Pro plus unlimited org members, SSO / SAML, audit logs, and dedicated support.",
  enterprise: "Everything in Teams with custom contracts, SLAs, and on-premise options.",
};

function PlanBadge({ plan }: { plan: SubscriptionPlan }) {
  const styles: Record<SubscriptionPlan, string> = {
    free: "text-[#9C988D] border border-[#2B2923]",
    pro: "text-[#D6FF3F] border border-[#D6FF3F]/30",
    teams: "text-[#F4F1E8] border border-[#F4F1E8]/20",
    enterprise: "text-[#D6FF3F] border border-[#D6FF3F]/30",
  };
  return (
    <span className={`font-mono text-[10px] uppercase tracking-widest px-2 py-0.5 ${styles[plan]}`}>
      {PLAN_LABELS[plan]}
    </span>
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

  const fetchStatus = useCallback(async () => {
    if (!sessionToken) {
      router.replace("/login");
      return;
    }
    try {
      const data = await api.billing.status(sessionToken);
      setStatus(data);
    } catch {
      setError("Failed to load billing status");
    } finally {
      setLoading(false);
    }
  }, [sessionToken, router]);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

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
      const msg = e instanceof Error ? e.message : "Failed to start checkout";
      setError(msg);
      setActionLoading(false);
    }
  };

  const openPortal = async () => {
    if (!sessionToken) return;
    setActionLoading(true);
    setError(null);
    try {
      const { url } = await api.billing.portal(
        { returnUrl: window.location.href },
        sessionToken,
      );
      window.location.href = url;
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to open billing portal";
      setError(msg);
      setActionLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#070706] flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-[#2B2923] border-t-[#D6FF3F] animate-spin" />
      </div>
    );
  }

  const plan = status?.plan ?? "free";
  const isActive = status?.status === "active" || status?.status === "trialing";
  const periodEnd = status?.currentPeriodEnd
    ? new Date(status.currentPeriodEnd).toLocaleDateString()
    : null;

  return (
    <div className="min-h-screen bg-[#070706]">
      <div className="max-w-2xl mx-auto px-6 py-12">
        <button
          onClick={() => router.back()}
          className="flex items-center gap-1.5 font-mono text-xs text-[#9C988D] hover:text-[#F4F1E8] mb-8 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
          Back to vault
        </button>

        <h1 className="font-mono text-2xl font-bold text-[#F4F1E8] mb-1">Billing</h1>
        <p className="text-sm text-[#9C988D] mb-8">
          Manage your nopwd subscription
        </p>

        {error && (
          <div className="mb-6 px-4 py-3 bg-[#E8321A]/10 border border-[#E8321A]/30 text-sm text-[#E8321A]">
            {error}
          </div>
        )}

        {/* Current plan */}
        <div className="bg-[#11110F] border border-[#2B2923] p-6 mb-6">
          <div className="flex items-start justify-between mb-3">
            <div>
              <p className="font-mono text-[10px] text-[#9C988D] uppercase tracking-widest mb-1">
                Current plan
              </p>
              <div className="flex items-center gap-2.5">
                <h2 className="font-mono text-lg font-semibold text-[#F4F1E8]">
                  {PLAN_LABELS[plan]}
                </h2>
                <PlanBadge plan={plan} />
              </div>
            </div>
            {plan !== "free" && isActive && (
              <button
                onClick={openPortal}
                disabled={actionLoading}
                className="font-mono text-xs text-[#D6FF3F] hover:underline disabled:opacity-50"
              >
                Manage billing
              </button>
            )}
          </div>
          <p className="text-sm text-[#9C988D] mb-4">
            {PLAN_DESCRIPTIONS[plan]}
          </p>
          {periodEnd && (
            <p className="font-mono text-xs text-[#9C988D]/60">
              {status?.status === "canceled" ? "Access until" : "Renews"}: {periodEnd}
            </p>
          )}
        </div>

        {/* Upgrade options */}
        {plan === "free" && (
          <>
            <h3 className="font-mono text-xs text-[#9C988D] uppercase tracking-widest mb-3">
              Upgrade your plan
            </h3>
            <div className="grid sm:grid-cols-2 gap-px bg-[#2B2923]">
              {/* Pro */}
              <div className="bg-[#11110F] p-5">
                <div className="flex items-center gap-2 mb-3">
                  <span className="font-mono text-sm font-semibold text-[#F4F1E8]">Pro</span>
                  <span className="font-mono text-[10px] uppercase tracking-widest px-2 py-0.5 text-[#D6FF3F] border border-[#D6FF3F]/30">
                    Popular
                  </span>
                </div>
                <div className="mb-4">
                  <span className="font-mono text-2xl font-bold text-[#F4F1E8]">€4</span>
                  <span className="text-sm text-[#9C988D]"> /month</span>
                  <p className="font-mono text-xs text-[#9C988D]/60 mt-0.5">
                    or €36/year (save 25%)
                  </p>
                </div>
                <ul className="space-y-1.5 mb-5">
                  {["File attachments (1 GB)", "Hardware key 2FA", "Emergency access", "REST API access"].map((f) => (
                    <li key={f} className="flex items-center gap-1.5 text-xs text-[#9C988D]">
                      <span className="font-mono text-[#D6FF3F] shrink-0">✓</span>
                      {f}
                    </li>
                  ))}
                </ul>
                <div className="flex flex-col gap-2">
                  {proMonthlyPriceId && (
                    <button
                      onClick={() => startCheckout(proMonthlyPriceId)}
                      disabled={actionLoading}
                      className="w-full py-2 font-mono text-xs font-semibold bg-[#D6FF3F] hover:bg-[#C4EE30] text-[#070706] transition-colors disabled:opacity-50"
                    >
                      {actionLoading ? "Loading…" : "Subscribe monthly"}
                    </button>
                  )}
                  {proAnnualPriceId && (
                    <button
                      onClick={() => startCheckout(proAnnualPriceId)}
                      disabled={actionLoading}
                      className="w-full py-2 font-mono text-xs border border-[#2B2923] text-[#9C988D] hover:border-[#9C988D] hover:text-[#F4F1E8] transition-colors disabled:opacity-50"
                    >
                      {actionLoading ? "Loading…" : "Subscribe yearly — €36"}
                    </button>
                  )}
                  {!proMonthlyPriceId && !proAnnualPriceId && (
                    <p className="font-mono text-xs text-[#9C988D]/60 text-center">Coming soon</p>
                  )}
                </div>
              </div>

              {/* Teams */}
              <div className="bg-[#11110F] p-5">
                <div className="flex items-center gap-2 mb-3">
                  <span className="font-mono text-sm font-semibold text-[#F4F1E8]">Teams</span>
                </div>
                <div className="mb-4">
                  <span className="font-mono text-2xl font-bold text-[#F4F1E8]">€5</span>
                  <span className="text-sm text-[#9C988D]"> /user/month</span>
                  <p className="font-mono text-xs text-[#9C988D]/60 mt-0.5">
                    Minimum 3 seats · annual billing
                  </p>
                </div>
                <ul className="space-y-1.5 mb-5">
                  {["Everything in Pro", "Unlimited org members", "SSO / SAML", "Audit logs"].map((f) => (
                    <li key={f} className="flex items-center gap-1.5 text-xs text-[#9C988D]">
                      <span className="font-mono text-[#9C988D] shrink-0">—</span>
                      {f}
                    </li>
                  ))}
                </ul>
                {teamsPriceId ? (
                  <button
                    onClick={() => startCheckout(teamsPriceId)}
                    disabled={actionLoading}
                    className="w-full py-2 font-mono text-xs border border-[#2B2923] text-[#9C988D] hover:border-[#9C988D] hover:text-[#F4F1E8] transition-colors disabled:opacity-50"
                  >
                    {actionLoading ? "Loading…" : "Start Teams trial"}
                  </button>
                ) : (
                  <p className="font-mono text-xs text-[#9C988D]/60 text-center">Coming soon</p>
                )}
              </div>
            </div>
          </>
        )}

        {/* Downgrade option */}
        {plan !== "free" && (
          <div className="mt-6 text-center">
            <button
              onClick={openPortal}
              disabled={actionLoading}
              className="font-mono text-xs text-[#9C988D] hover:text-[#F4F1E8] disabled:opacity-50 transition-colors"
            >
              Cancel subscription or change plan
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
