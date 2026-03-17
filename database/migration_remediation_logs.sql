-- Migration: Create remediation_logs table for Anga AutoFix
-- Feature: Anga AutoFix - Premium auto-remediation service
--
-- This table stores the history of all remediation executions,
-- including credits charged, actions taken, and results.
--
-- Apply this migration to Supabase database via SQL Editor:
-- https://supabase.com/dashboard/project/xlhdhxfknqjqzdohtlii/sql

-- Create the remediation_logs table
CREATE TABLE IF NOT EXISTS remediation_logs (
    execution_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES security_accounts(id) ON DELETE CASCADE,
    zone_id TEXT NOT NULL,
    zone_name TEXT,
    control_id TEXT,
    control_name TEXT,
    actions_executed INTEGER DEFAULT 0,
    actions_succeeded INTEGER DEFAULT 0,
    actions_failed INTEGER DEFAULT 0,
    credits_charged INTEGER DEFAULT 0,
    credits_refunded INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'partial', 'failed', 'refunded')),
    actions_json JSONB,
    results_json JSONB,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_remediation_logs_account_id ON remediation_logs(account_id);
CREATE INDEX IF NOT EXISTS idx_remediation_logs_zone_id ON remediation_logs(zone_id);
CREATE INDEX IF NOT EXISTS idx_remediation_logs_status ON remediation_logs(status);
CREATE INDEX IF NOT EXISTS idx_remediation_logs_created_at ON remediation_logs(created_at DESC);

-- Enable RLS
ALTER TABLE remediation_logs ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their own remediation logs
CREATE POLICY "Users can view own remediation logs"
    ON remediation_logs
    FOR SELECT
    USING (account_id IN (
        SELECT id FROM security_accounts WHERE user_id = auth.uid()
    ));

-- Policy: Service role can insert/update (for API operations)
CREATE POLICY "Service role can manage remediation logs"
    ON remediation_logs
    FOR ALL
    USING (true)
    WITH CHECK (true);

-- Grant permissions
GRANT SELECT ON remediation_logs TO authenticated;
GRANT ALL ON remediation_logs TO service_role;

-- Add comment for documentation
COMMENT ON TABLE remediation_logs IS 'Stores Anga AutoFix execution history - premium auto-remediation service (500 credits per fix)';
COMMENT ON COLUMN remediation_logs.execution_id IS 'Unique identifier for this remediation execution';
COMMENT ON COLUMN remediation_logs.actions_json IS 'JSON array of RemediationAction objects that were executed';
COMMENT ON COLUMN remediation_logs.results_json IS 'JSON array of execution results for each action';

-- Verify the table was created:
-- SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_name = 'remediation_logs';
