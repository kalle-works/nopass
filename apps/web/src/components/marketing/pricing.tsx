import Link from "next/link";
import { Section } from "./container";
import { linkButton } from "./link-button";

interface Plan {
  name: string;
  price: string;
  unit?: string;
  note: string;
  cta: string;
  href: string;
  features: string[];
}

const PLANS: Plan[] = [
  {
    name: "Free",
    price: "€0",
    note: "Free forever",
    cta: "Create your vault",
    href: "/register",
    features: [
      "Unlimited vault items",
      "Sync across all devices",
      "Browser extensions",
      "macOS desktop app with Touch ID",
      "Team vault for up to 3 members",
      "Open source",
    ],
  },
  {
    name: "Pro",
    price: "€4",
    unit: "per month",
    note: "or €36 per year, 25% less",
    cta: "Upgrade to Pro",
    href: "/vault/billing",
    features: [
      "Everything in Free",
      "Encrypted file attachments",
      "Hardware key 2FA",
      "Emergency access",
      "REST API access",
      "Priority support",
    ],
  },
  {
    name: "Teams",
    price: "€5",
    unit: "per seat, per month",
    note: "Minimum 3 seats, billed annually",
    cta: "Start a Teams trial",
    href: "/vault/billing",
    features: ["Everything in Pro", "Unlimited org members", "SSO / SAML", "Audit logs", "Dedicated support"],
  },
];

export function Pricing() {
  return (
    <Section id="pricing" title="Pricing" intro="Start free. Upgrade when you need more.">
      <div className="grid overflow-hidden rounded-lg border border-divider md:grid-cols-3">
        {PLANS.map((plan) => (
          <div
            key={plan.name}
            className="flex flex-col border-b border-divider p-6 last:border-b-0 md:border-b-0 md:border-r md:last:border-r-0"
          >
            <h3 className="text-h3 font-semibold text-fg">{plan.name}</h3>
            <p className="mt-4 flex items-baseline gap-2">
              <span className="text-h1 font-semibold tabular-nums text-fg">{plan.price}</span>
              {plan.unit && <span className="text-ui text-muted">{plan.unit}</span>}
            </p>
            <p className="mt-1 text-meta text-muted">{plan.note}</p>
            <Link href={plan.href} className={`${linkButton("secondary")} mt-6`}>
              {plan.cta}
            </Link>
            <ul className="mt-6 space-y-2 border-t border-divider pt-6 text-ui text-muted">
              {plan.features.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Section>
  );
}
