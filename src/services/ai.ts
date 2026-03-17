/**
 * Anga Security — AI Service
 * 
 * Provides AI-powered features using Workers AI (Llama 3.1):
 * - Security report analysis
 * - Remediation recommendations
 * - WAF rule generation
 * - General security Q&A
 */

import type { Env, ChatMessage } from '../types';

// Model configuration
const MODEL = '@cf/meta/llama-3.1-8b-instruct';
const MAX_TOKENS = 2048;
const TEMPERATURE = 0.7;

// System prompts for different contexts
const SYSTEM_PROMPTS = {
  general: `You are an expert Cloudflare security consultant specializing in web application security, 
DDoS protection, WAF configuration, and security best practices. You help users understand security 
reports, implement fixes, and optimize their Cloudflare security settings. Be concise, technical, 
and actionable.`,

  audit: `You are analyzing a Cloudflare Security Audit report. Help the user understand findings, 
prioritize fixes, and implement security improvements. Focus on practical, step-by-step guidance 
for Cloudflare configurations.`,

  simulation: `You are analyzing an Attack Simulation report showing how 75+ real attack payloads 
performed against the site. Help explain which attacks were blocked, which bypassed defenses, and 
how to strengthen security rules.`,

  compliance: `You are analyzing a compliance mapping report (PCI DSS, HIPAA, ISO 27001, SOC 2, GDPR). 
Help the user understand which controls pass/fail and provide remediation steps to achieve compliance.`,
};

/**
 * Call Workers AI with chat messages
 */
export async function chat(
  ai: Ai,
  messages: ChatMessage[],
  context: 'general' | 'audit' | 'simulation' | 'compliance' = 'general'
): Promise<{ message: string; tokens_used?: number }> {
  try {
    // Prepend system prompt based on context
    const systemPrompt: ChatMessage = {
      role: 'system',
      content: SYSTEM_PROMPTS[context],
    };

    const fullMessages = [systemPrompt, ...messages];

    // Call Workers AI
    const response = await ai.run(MODEL, {
      messages: fullMessages,
      max_tokens: MAX_TOKENS,
      temperature: TEMPERATURE,
    });

    // Extract response
    const aiResponse = response as { response?: string; tokens_used?: number };
    
    return {
      message: aiResponse.response || 'Lo siento, no pude generar una respuesta.',
      tokens_used: aiResponse.tokens_used,
    };
  } catch (error) {
    console.error('AI chat error:', error);
    throw new Error('Failed to get AI response');
  }
}

/**
 * Generate a security summary for a report
 */
export async function generateReportSummary(
  ai: Ai,
  reportType: 'audit' | 'simulation' | 'compliance',
  reportData: any
): Promise<string> {
  try {
    let prompt = '';

    if (reportType === 'audit') {
      const score = reportData.overall_score || 0;
      const grade = reportData.grade || 'N/A';
      const criticalCount = reportData.summary?.critical_findings || 0;
      const highCount = reportData.summary?.high_findings || 0;

      prompt = `Analyze this Cloudflare Security Audit:
- Overall Score: ${score}/100 (Grade: ${grade})
- Critical Issues: ${criticalCount}
- High Priority Issues: ${highCount}

Provide a 2-3 sentence executive summary highlighting the most important findings and recommended actions.`;
    } else if (reportType === 'simulation') {
      const attacksBlocked = reportData.summary?.attacks_blocked || 0;
      const attacksBypassed = reportData.summary?.attacks_bypassed || 0;
      const totalAttacks = attacksBlocked + attacksBypassed;

      prompt = `Analyze this Attack Simulation:
- Total Attacks Tested: ${totalAttacks}
- Attacks Blocked: ${attacksBlocked}
- Attacks Bypassed: ${attacksBypassed}

Provide a 2-3 sentence executive summary highlighting the security posture and recommended improvements.`;
    } else if (reportType === 'compliance') {
      const passed = reportData.summary?.passed || 0;
      const failed = reportData.summary?.failed || 0;
      const coverage = reportData.summary?.coverage_pct || 0;

      prompt = `Analyze this Compliance Report:
- Controls Passed: ${passed}
- Controls Failed: ${failed}
- Coverage: ${coverage}%

Provide a 2-3 sentence executive summary highlighting compliance status and gaps.`;
    }

    const response = await ai.run(MODEL, {
      messages: [
        { role: 'system', content: SYSTEM_PROMPTS[reportType] },
        { role: 'user', content: prompt },
      ],
      max_tokens: 512,
      temperature: 0.5, // Lower temperature for summaries
    });

    const aiResponse = response as { response?: string };
    return aiResponse.response || 'Summary not available.';
  } catch (error) {
    console.error('AI summary generation error:', error);
    return 'Unable to generate AI summary.';
  }
}

/**
 * Generate remediation steps for a specific finding
 */
export async function generateRemediationSteps(
  ai: Ai,
  finding: string,
  context: string
): Promise<string[]> {
  try {
    const prompt = `Given this security finding: "${finding}"
Context: ${context}

Provide 3-5 specific, actionable remediation steps for Cloudflare configuration. Format as a numbered list.`;

    const response = await ai.run(MODEL, {
      messages: [
        { role: 'system', content: SYSTEM_PROMPTS.general },
        { role: 'user', content: prompt },
      ],
      max_tokens: 1024,
      temperature: 0.6,
    });

    const aiResponse = response as { response?: string };
    const text = aiResponse.response || '';

    // Parse numbered list
    const steps = text
      .split('\n')
      .filter((line) => /^\d+\./.test(line.trim()))
      .map((line) => line.trim());

    return steps.length > 0 ? steps : ['Configure via Cloudflare Dashboard'];
  } catch (error) {
    console.error('AI remediation generation error:', error);
    return ['Review Cloudflare documentation for remediation steps'];
  }
}

/**
 * Generate WAF rule suggestions based on attack patterns
 */
export async function generateWAFRule(
  ai: Ai,
  attackType: string,
  payload: string
): Promise<string> {
  try {
    const prompt = `Generate a Cloudflare WAF custom rule to block this attack:
Type: ${attackType}
Payload: ${payload}

Provide the rule expression using Cloudflare's rule syntax. Be specific and avoid false positives.`;

    const response = await ai.run(MODEL, {
      messages: [
        { role: 'system', content: 'You are a Cloudflare WAF expert. Generate precise WAF rules.' },
        { role: 'user', content: prompt },
      ],
      max_tokens: 512,
      temperature: 0.4, // Low temperature for precise rules
    });

    const aiResponse = response as { response?: string };
    return aiResponse.response || '(http.request.uri.path contains "/malicious")';
  } catch (error) {
    console.error('AI WAF rule generation error:', error);
    return '(http.request.uri.query contains "malicious")';
  }
}
