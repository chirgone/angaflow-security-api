/**
 * AI Routes
 * POST /api/ai/chat — Chat with AI about security topics
 * POST /api/ai/summary/:report_id — Generate AI summary for a report
 */

import { Hono } from 'hono';
import type { Env, Variables, ChatRequest, ChatResponse } from '../types';
import { chat, generateReportSummary } from '../services/ai';
import { getAdminClient } from '../services/supabase';

const ai = new Hono<{ Bindings: Env; Variables: Variables }>();

// ════════════════════════════════════════════════════════════════════
// POST /chat — AI Chat Endpoint
// ════════════════════════════════════════════════════════════════════

ai.post('/chat', async (c) => {
  const userId = c.get('userId');

  const body = await c.req.json<ChatRequest>().catch(() => ({} as ChatRequest));
  const { messages, context = 'general', report_id } = body;

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return c.json({ error: 'Messages array is required' }, 400);
  }

  // Validate message format
  for (const msg of messages) {
    if (!msg.role || !msg.content) {
      return c.json({ error: 'Each message must have role and content' }, 400);
    }
    if (!['user', 'assistant', 'system'].includes(msg.role)) {
      return c.json({ error: 'Invalid message role' }, 400);
    }
  }

  // Optional: Load report data if report_id provided for context
  let reportContext = '';
  if (report_id) {
    const admin = getAdminClient(c.env);
    const { data: account } = await admin
      .from('security_accounts')
      .select('id')
      .eq('user_id', userId)
      .single();

    if (account) {
      const { data: report } = await admin
        .from('security_reports')
        .select('report_type, score, grade, data')
        .eq('id', report_id)
        .eq('account_id', account.id)
        .single();

      if (report) {
        reportContext = `\n\nReport context: Type=${report.report_type}, Score=${report.score}, Grade=${report.grade}`;
      }
    }
  }

  // Add report context to last message if available
  if (reportContext && messages.length > 0) {
    const lastMsg = messages[messages.length - 1];
    if (lastMsg.role === 'user') {
      lastMsg.content += reportContext;
    }
  }

  try {
    const response = await chat(c.env.AI, messages, context);
    
    return c.json<ChatResponse>({
      message: response.message,
      tokens_used: response.tokens_used,
    });
  } catch (error) {
    console.error('Chat endpoint error:', error);
    return c.json({ error: 'Failed to get AI response' }, 500);
  }
});

// ════════════════════════════════════════════════════════════════════
// POST /summary/:report_id — Generate AI Summary for Report
// ════════════════════════════════════════════════════════════════════

ai.post('/summary/:report_id', async (c) => {
  const userId = c.get('userId');
  const reportId = c.req.param('report_id');
  const admin = getAdminClient(c.env);

  // Get user account
  const { data: account } = await admin
    .from('security_accounts')
    .select('id')
    .eq('user_id', userId)
    .single();

  if (!account) {
    return c.json({ error: 'Account not found' }, 404);
  }

  // Get report
  const { data: report, error } = await admin
    .from('security_reports')
    .select('*')
    .eq('id', reportId)
    .eq('account_id', account.id)
    .single();

  if (error || !report) {
    return c.json({ error: 'Report not found' }, 404);
  }

  if (!['audit', 'simulation', 'compliance'].includes(report.report_type)) {
    return c.json({ error: 'AI summaries only available for audit, simulation, and compliance reports' }, 400);
  }

  try {
    const summary = await generateReportSummary(
      c.env.AI,
      report.report_type as 'audit' | 'simulation' | 'compliance',
      report.data
    );

    return c.json({ summary });
  } catch (error) {
    console.error('Summary generation error:', error);
    return c.json({ error: 'Failed to generate summary' }, 500);
  }
});

export default ai;
