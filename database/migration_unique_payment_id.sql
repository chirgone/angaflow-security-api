-- Migration: Add UNIQUE constraint on payment_id to prevent double-crediting
-- Sprint 0.7: Security Hardening - Fix H2 (double-crediting TOCTOU)
--
-- This constraint ensures that even if concurrent webhooks arrive, only one
-- can successfully insert a payment log, preventing double-crediting.
--
-- Apply this migration to Supabase database via SQL Editor:
-- https://supabase.com/dashboard/project/xlhdhxfknqjqzdohtlii/sql

ALTER TABLE security_payment_logs
ADD CONSTRAINT security_payment_logs_payment_id_unique
UNIQUE (payment_id);

-- Verify the constraint was added:
-- SELECT conname, contype FROM pg_constraint WHERE conrelid = 'security_payment_logs'::regclass;
