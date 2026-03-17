/**
 * Execute SQL migration via Supabase REST API
 * Runs the security_leads table migration
 */

import { readFileSync } from 'fs';

const SUPABASE_URL = 'https://xlhdhxfknqjqzdohtlii.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_SERVICE_KEY) {
  console.error('❌ SUPABASE_SERVICE_ROLE_KEY environment variable is required');
  console.log('Run: export SUPABASE_SERVICE_ROLE_KEY="your-key-here"');
  process.exit(1);
}

const sql = readFileSync('./migrations/006_create_security_leads.sql', 'utf-8');

console.log('🚀 Executing migration: 006_create_security_leads.sql');
console.log('📊 SQL length:', sql.length, 'characters');

// Supabase REST API doesn't have a direct SQL execution endpoint for service role
// We need to use the PostgREST SQL function or execute via HTTP
// The best approach is to use Supabase Management API or execute each statement separately

// For now, let's try the pg_query approach using rpc
const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/exec_sql`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'apikey': SUPABASE_SERVICE_KEY,
    'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
  },
  body: JSON.stringify({ query: sql }),
});

if (!response.ok) {
  const error = await response.text();
  console.error('❌ Migration failed:', response.status, error);
  
  // If the RPC doesn't exist, we need to execute via direct PostgreSQL connection
  // For now, print the SQL for manual execution
  console.log('\n📋 Manual execution required. Copy this SQL to Supabase SQL Editor:');
  console.log('=' .repeat(60));
  console.log(sql);
  console.log('=' .repeat(60));
  process.exit(1);
}

const data = await response.json();
console.log('✅ Migration completed successfully');
console.log('Response:', data);
