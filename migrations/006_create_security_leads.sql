-- Migration: Create security_leads table
-- Purpose: Store contact leads from "Need Help?" section
-- Author: Jose Anguiano
-- Date: 2026-03-10

CREATE TABLE IF NOT EXISTS security_leads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    company TEXT,
    domain TEXT NOT NULL,
    message TEXT NOT NULL,
    ownership_confirmed BOOLEAN NOT NULL DEFAULT false,
    domain_uses_cloudflare BOOLEAN DEFAULT NULL,
    domain_exists BOOLEAN DEFAULT NULL,
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'contacted', 'qualified', 'closed', 'discarded')),
    notes TEXT,
    user_id UUID REFERENCES security_accounts(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_security_leads_email ON security_leads(email);
CREATE INDEX idx_security_leads_domain ON security_leads(domain);
CREATE INDEX idx_security_leads_status ON security_leads(status);
CREATE INDEX idx_security_leads_created_at ON security_leads(created_at DESC);
CREATE INDEX idx_security_leads_user_id ON security_leads(user_id);

-- Trigger to update updated_at
CREATE OR REPLACE FUNCTION update_security_leads_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_security_leads_updated_at
    BEFORE UPDATE ON security_leads
    FOR EACH ROW
    EXECUTE FUNCTION update_security_leads_updated_at();

-- Enable RLS
ALTER TABLE security_leads ENABLE ROW LEVEL SECURITY;

-- Policy: Only admins can read all leads (handled by backend admin middleware)
-- No direct user access policies needed since all access goes through API
CREATE POLICY "Admin full access" ON security_leads
    FOR ALL
    TO authenticated
    USING (true)
    WITH CHECK (true);

COMMENT ON TABLE security_leads IS 'Contact leads from landing page Need Help section';
COMMENT ON COLUMN security_leads.ownership_confirmed IS 'User confirmed they own/manage the domain';
COMMENT ON COLUMN security_leads.domain_uses_cloudflare IS 'Automatically validated via DNS nameserver check';
COMMENT ON COLUMN security_leads.domain_exists IS 'Domain has valid DNS records';
COMMENT ON COLUMN security_leads.status IS 'Lead lifecycle: new -> contacted -> qualified -> closed/discarded';
