// Spiral Trust Scan core: a faithful copy of analyzeTrustSurface from
// backend/index.ts (the free web scanner), so the CLI and the web scanner
// give the same findings. test/backend/trust-scan-cli-parity.test.ts fails
// if the two ever drift apart. Pure function: no network, no filesystem.
import crypto from "node:crypto";

function trustFinding(id, severity, category, title, evidence, recommendation) {
  return { id, severity, category, title, evidence: evidence.slice(0, 260), recommendation };
}

function redactScannerSecrets(value) {
  return value
    .replace(/sk_(?:live|test)_[A-Za-z0-9]+/g, '[REDACTED_STRIPE_KEY]')
    .replace(/gh[pousr]_[A-Za-z0-9_]+/g, '[REDACTED_GITHUB_TOKEN]')
    .replace(/xox[baprs]-[A-Za-z0-9-]+/g, '[REDACTED_SLACK_TOKEN]')
    .replace(/Bearer\s+[A-Za-z0-9._~+\\/=-]+/gi, 'Bearer [REDACTED]')
    .replace(/AKIA[0-9A-Z]{16}/g, '[REDACTED_AWS_KEY]');
}

export function analyzeTrustSurface(sourceType, sourceLabel, rawSource) {
  const source = redactScannerSecrets(rawSource.slice(0, 120_000));
  const findings = [];
  const hasToolCall = /(tool_call|toolcall|function_call|function\s+\w+\s*\(|tool\s*[:=]|execute\s*\(|invoke\s*\()/i.test(source);
  const externalEffect = /(fetch\s*\(|axios|stripe\.|db\.(add|update|delete)|send\s*\(|publish\s*\(|approve\s*\(|deny\s*\(|transfer\s*\(|charge\s*\(|refund\s*\()/i.test(source);
  const authorization = /(authorize|authorization|permission|role|scope|policy|policyengine|requestintent|admin|isadmin|guard|allowlist)/i.test(source);
  const observation = /(receipt|ledger|evidence|observed|verification|verify|proof|trace|result|payment_status|stripeeventid)/i.test(source);
  const idempotency = /(idempotenc|dedup|eventid|stripeeventid|already.?processed|lock|lease|unique)/i.test(source);
  const confirmation = /(confirm|approval|human.?in.?the.?loop|two.?step|dry.?run)/i.test(source);
  const secretPattern = /(sk_(?:live|test)_|gh[pousr]_|xox[baprs]-|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._~+\/=-]{16,})/i.test(rawSource);
  const promptInjection = /(ignore (all|any|the) previous|system prompt|jailbreak|disregard instructions|developer message)/i.test(source);
  const toolCallsDetected = (source.match(/(tool_call|toolcall|function_call|function\s+\w+\s*\(|tool\s*[:=]|execute\s*\(|invoke\s*\()/gi) ?? []).length;

  if (secretPattern) {
    findings.push(trustFinding('secret-exposure', 'CRITICAL', 'SECRETS', 'Credential material appears in the scanned surface', 'A token or credential-like pattern was detected in the submitted material.', 'Remove secrets from prompts, logs and source; rotate exposed credentials and inject them only through server-side secret storage.'));
  }
  if (promptInjection && (sourceType === 'tool_log' || hasToolCall)) {
    findings.push(trustFinding('untrusted-instruction', 'HIGH', 'INPUT_TRUST', 'Untrusted instructions appear adjacent to tool execution', 'The scanned surface contains prompt-injection language near executable/tool-call material.', 'Treat external text as data, isolate it from control instructions, and require policy authorization before consequential tool calls.'));
  }
  if (hasToolCall && externalEffect && !authorization) {
    findings.push(trustFinding('authorization-gap', 'HIGH', 'AUTHORIZATION', 'Tool execution has no visible authorization gate', 'Tool/external-effect patterns were found without a recognizable authorization, policy or permission gate.', 'Insert an explicit Intent → Authorization gate before execution and fail closed when authorization is absent.'));
  }
  if (externalEffect && !observation) {
    findings.push(trustFinding('unverifiable-effect', 'HIGH', 'OBSERVATION', 'External effects lack independent evidence', 'The surface can perform an external effect but contains no recognizable receipt, ledger, observation or verification path.', 'Record the observed effect independently of the agent claim and bind it to a durable receipt.'));
  }
  if (externalEffect && !idempotency) {
    findings.push(trustFinding('replay-risk', 'MEDIUM', 'IDEMPOTENCY', 'No replay/idempotency control is visible', 'External side effects are present without an obvious deduplication, idempotency key, lock or lease.', 'Make retries safe with a stable operation identity and explicit replay protection.'));
  }
  if (externalEffect && !confirmation && /(delete|refund|transfer|charge|publish|approve|deny|send)/i.test(source)) {
    findings.push(trustFinding('irreversible-action', 'MEDIUM', 'EXECUTION', 'Irreversible actions lack a visible confirmation boundary', 'A potentially consequential action appears without an explicit confirmation, approval or dry-run boundary.', 'Separate planning from execution and require a policy-approved confirmation for irreversible actions.'));
  }
  if (hasToolCall && !authorization && !externalEffect) {
    findings.push(trustFinding('tool-governance', 'MEDIUM', 'AUTHORIZATION', 'Tool calls are visible but governance is unclear', 'Tool-call patterns were detected without enough evidence of a policy or permission boundary.', 'Make the authorization decision explicit and observable for every tool call.'));
  }
  if (hasToolCall && observation && authorization && !findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')) {
    findings.push(trustFinding('partial-assurance', 'LOW', 'OBSERVATION', 'Execution path shows signs of governance and evidence', 'Authorization and observation signals are present, but this free scan cannot prove runtime correspondence.', 'Run continuous verification against real receipts to prove authorized intent against observed effect.'));
  }

  const summary = {
    toolCallsDetected,
    criticalFindings: findings.filter((f) => f.severity === 'CRITICAL').length,
    highFindings: findings.filter((f) => f.severity === 'HIGH').length,
    mediumFindings: findings.filter((f) => f.severity === 'MEDIUM').length,
    lowFindings: findings.filter((f) => f.severity === 'LOW').length,
    authorizationGaps: findings.filter((f) => f.category === 'AUTHORIZATION').length,
    unverifiableEffects: findings.filter((f) => f.category === 'OBSERVATION').length,
  };
  const inputHash = crypto.createHash('sha256').update(sourceType + ':' + rawSource).digest('hex');
  const reportId = 'tscan_' + inputHash.slice(0, 24);
  return { reportId, sourceType, sourceLabel, scannedAt: new Date().toISOString(), summary, findings };
}
