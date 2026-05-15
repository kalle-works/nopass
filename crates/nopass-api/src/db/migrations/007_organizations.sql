CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    created_by  UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 'owner' | 'admin' | 'member'
-- status: 'pending' = invited, not yet accepted; 'active' = full member
-- encrypted_org_key: the org's AES-256-GCM key encrypted with the member's RSA-OAEP public key (base64)
CREATE TABLE organization_members (
    org_id              UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role                TEXT NOT NULL DEFAULT 'member'
                            CHECK (role IN ('owner', 'admin', 'member')),
    status              TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'active')),
    encrypted_org_key   TEXT,
    invited_by          UUID REFERENCES users(id),
    joined_at           TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, user_id)
);

-- Org vault items live in vault_items with an org_id set.
-- Personal items have org_id = NULL.
ALTER TABLE vault_items
    ADD COLUMN org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX idx_vault_items_org ON vault_items (org_id) WHERE org_id IS NOT NULL;
CREATE INDEX idx_org_members_user ON organization_members (user_id);
