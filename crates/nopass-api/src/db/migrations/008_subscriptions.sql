CREATE TYPE subscription_plan AS ENUM ('free', 'pro', 'teams', 'enterprise');
CREATE TYPE subscription_status AS ENUM ('active', 'past_due', 'canceled', 'trialing');

CREATE TABLE subscriptions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan                    subscription_plan NOT NULL DEFAULT 'free',
    status                  subscription_status NOT NULL DEFAULT 'active',
    stripe_customer_id      TEXT,
    stripe_subscription_id  TEXT,
    current_period_end      TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_subscriptions_user_id
    ON subscriptions (user_id);

CREATE INDEX idx_subscriptions_stripe_customer
    ON subscriptions (stripe_customer_id)
    WHERE stripe_customer_id IS NOT NULL;
