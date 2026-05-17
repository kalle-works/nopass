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
  const colors: Record<SubscriptionPlan, string> = {
    free: "bg-white/5 text-white/40 border border-white/10",
    pro: "bg-blue-500/20 text-blue-300 border border-blue-500/30",
    teams: "bg-violet-500/20 text-violet-300 border border-violet-500/30",
    enterprise: "bg-amber-500/20 text-amber-300 border border-amber-500/30",
  };
  return (
    <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${colors[plan]}`}>
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
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  const plan = status?.plan ?? "free";
  const isActive = status?.status === "active" || status?.status === "trialing";
  const periodEnd = status?.currentPeriodEnd
    ? new Date(status.currentPeriodEnd).toLocaleDateString()
    : null;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <div className="max-w-2xl mx-auto px-6 py-12">
        <button
          onClick={() => router.back()}
          className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 mb-8 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
          Back to vault
        </button>

        <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-1">Billing</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-8">
          Manage your nopwd subscription
        </p>

        {error && (
          <div className="mb-6 px-4 py-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm text-red-700 dark:text-red-400">
            {error}
          </div>
        )}

        {/* Current plan */}
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6 mb-6">
          <div className="flex items-start justify-between mb-3">
            <div>
              <p className="text-xs font-medium text-gray-400 dark:text-gray-500 uppercase tracking-widest mb-1">
                Current plan
              </p>
              <div className="flex items-center gap-2.5">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {PLAN_LABELS[plan]}
                </h2>
                <PlanBadge plan={plan} />
              </div>
            </div>
            {plan !== "free" && isActive && (
              <button
                onClick={openPortal}
                disabled={actionLoading}
                className="text-sm text-blue-600 dark:text-blue-400 hover:underline disabled:opacity-50"
              >
                Manage billing
              </button>
            )}
          </div>
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
            {PLAN_DESCRIPTIONS[plan]}
          </p>
          {periodEnd && (
            <p className="text-xs text-gray-400 dark:text-gray-500">
              {status?.status === "canceled" ? "Access until" : "Renews"}: {periodEnd}
            </p>
          )}
        </div>

        {/* Upgrade options — shown when on free plan */}
        {plan === "free" && (
          <>
            <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
              Upgrade your plan
            </h3>
            <div className="grid sm:grid-cols-2 gap-4">
              {/* Pro */}
              <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-sm font-semibold text-gray-900 dark:text-white">Pro</span>
                  <span className="text-xs px-2 py-0.5 rounded-full bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300 border border-blue-200 dark:border-blue-800">
                    Popular
                  </span>
                </div>
                <div className="mb-4">
                  <span className="text-2xl font-bold text-gray-900 dark:text-white">€4</span>
                  <span className="text-sm text-gray-400 dark:text-gray-500"> /month</span>
                  <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">
                    or €36/year (save 25%)
                  </p>
                </div>
                <ul className="space-y-1.5 mb-5 text-xs text-gray-500 dark:text-gray-400">
                  {["File attachments (1 GB)", "Hardware key 2FA", "Emergency access", "REST API access"].map((f) => (
                    <li key={f} className="flex items-center gap-1.5">
                      <svg className="w-3.5 h-3.5 text-blue-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                      {f}
                    </li>
                  ))}
                </ul>
                <div className="flex flex-col gap-2">
                  {proMonthlyPriceId && (
                    <button
                      onClick={() => startCheckout(proMonthlyPriceId)}
                      disabled={actionLoading}
                      className="w-full py-2 rounded-lg bg-blue-600 text-white text-sm font-medium hover:bg-blue-500 transition-colors disabled:opacity-50"
                    >
                      {actionLoading ? "Loading…" : "Subscribe monthly"}
                    </button>
                  )}
                  {proAnnualPriceId && (
                    <button
                      onClick={() => startCheckout(proAnnualPriceId)}
                      disabled={actionLoading}
                      className="w-full py-2 rounded-lg border border-blue-200 dark:border-blue-800 text-blue-600 dark:text-blue-400 text-sm font-medium hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-colors disabled:opacity-50"
                    >
                      {actionLoading ? "Loading…" : "Subscribe yearly — €36"}
                    </button>
                  )}
                  {!proMonthlyPriceId && !proAnnualPriceId && (
                    <p className="text-xs text-gray-400 text-center">Coming soon</p>
                  )}
                </div>
              </div>

              {/* Teams */}
              <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-sm font-semibold text-gray-900 dark:text-white">Teams</span>
                </div>
                <div className="mb-4">
                  <span className="text-2xl font-bold text-gray-900 dark:text-white">€5</span>
                  <span className="text-sm text-gray-400 dark:text-gray-500"> /user/month</span>
                  <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">
                    Minimum 3 seats · annual billing
                  </p>
                </div>
                <ul className="space-y-1.5 mb-5 text-xs text-gray-500 dark:text-gray-400">
                  {["Everything in Pro", "Unlimited org members", "SSO / SAML", "Audit logs"].map((f) => (
                    <li key={f} className="flex items-center gap-1.5">
                      <svg className="w-3.5 h-3.5 text-violet-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                      {f}
                    </li>
                  ))}
                </ul>
                {teamsPriceId ? (
                  <button
                    onClick={() => startCheckout(teamsPriceId)}
                    disabled={actionLoading}
                    className="w-full py-2 rounded-lg bg-violet-600 text-white text-sm font-medium hover:bg-violet-500 transition-colors disabled:opacity-50"
                  >
                    {actionLoading ? "Loading…" : "Start Teams trial"}
                  </button>
                ) : (
                  <p className="text-xs text-gray-400 text-center">Coming soon</p>
                )}
              </div>
            </div>
          </>
        )}

        {/* Downgrade option for paid plans */}
        {plan !== "free" && (
          <div className="mt-6 text-center">
            <button
              onClick={openPortal}
              disabled={actionLoading}
              className="text-sm text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 disabled:opacity-50 transition-colors"
            >
              Cancel subscription or change plan
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
