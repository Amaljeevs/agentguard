export type AgentType = 'ASSISTANT' | 'AUTONOMOUS' | 'WORKER' | 'SYSTEM';
export type DecisionType = 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED';

export interface AgentIdentity {
  agentId: string;
  agentType: AgentType;
  roles: string[];
  permissions: string[];
  delegatedBy?: string;
  sessionId?: string;
  issuedAt: string;
  expiresAt: string;
  attributes?: Record<string, unknown>;
}

export interface Action {
  name: string;
  parameters: Record<string, unknown>;
}

export interface Resource {
  type: string;
  id: string;
  tags?: Record<string, string>;
}

export interface AuthorizationContext {
  environment: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface AuthorizationRequest {
  subject: AgentIdentity;
  action: Action;
  resource: Resource;
  context: AuthorizationContext;
}

export interface EvaluationTraceStep {
  step: string;
  status: 'passed' | 'failed' | 'triggered' | 'skipped';
  details: string;
}

export interface AuthorizationDecision {
  decision: DecisionType;
  reason: string;
  matchedPolicyName?: string;
  matchedRuleId?: string;
  evaluatedAt: string;
  trace: EvaluationTraceStep[];
}

export function matchPermission(pattern: string, action: string): boolean {
  if (!pattern || !action) return false;
  const p = pattern.trim();
  const a = action.trim();
  if (p === '*') return true;
  if (p === a) return true;

  if (p.includes('*')) {
    const regexStr = '^' + p.split('*').map(s => s.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')).join('.*') + '$';
    try {
      const reg = new RegExp(regexStr);
      return reg.test(a);
    } catch {
      return false;
    }
  }
  return false;
}

export interface RoleDef {
  description?: string;
  permissions: string[];
}

export interface PolicyRuleDef {
  id: string;
  description?: string;
  effect: DecisionType;
  targetRoles?: string[];
  targetActions?: string[];
  resourceType?: string;
  resourceId?: string;
  environments?: string[];
}

export interface PolicySetDef {
  name: string;
  version: string;
  roles: Record<string, RoleDef>;
  rules: PolicyRuleDef[];
}

export const DEFAULT_POLICY: PolicySetDef = {
  name: 'enterprise-mcp-governance',
  version: '1.0',
  roles: {
    developer: {
      description: 'Standard software development assistant',
      permissions: ['git.read', 'git.write', 'logs.read', 'database.query'],
    },
    devops: {
      description: 'Infrastructure and deployment management agent',
      permissions: ['logs.read', 'kubernetes.*', 'database.*'],
    },
    'security-auditor': {
      description: 'Read-only compliance and audit agent',
      permissions: ['*.read'],
    },
    admin: {
      description: 'Universal administrator agent',
      permissions: ['*'],
    },
  },
  rules: [
    {
      id: 'deny-dev-prod-db',
      description: 'Developers cannot query or write to databases in production',
      effect: 'DENY',
      targetRoles: ['developer'],
      targetActions: ['database.query', 'database.write'],
      resourceType: 'database',
      environments: ['production'],
    },
    {
      id: 'prod-deploy-approval',
      description: 'Deploying to Kubernetes in production requires human approval',
      effect: 'APPROVAL_REQUIRED',
      targetActions: ['kubernetes.deploy'],
      environments: ['production'],
    },
    {
      id: 'deny-destructive-drop-prod',
      description: 'Explicitly deny database drop/truncate across all agents in production',
      effect: 'DENY',
      targetActions: ['database.drop', 'database.truncate'],
      environments: ['production'],
    },
  ],
};

export function evaluatePolicy(
  policy: PolicySetDef,
  req: AuthorizationRequest
): AuthorizationDecision {
  const trace: EvaluationTraceStep[] = [];
  const now = new Date(req.context.timestamp).getTime();
  const expiresAt = new Date(req.subject.expiresAt).getTime();

  // Step 1: Expiration check
  if (now > expiresAt) {
    trace.push({
      step: 'Identity Validity Check',
      status: 'failed',
      details: `Subject identity '${req.subject.agentId}' expired at ${req.subject.expiresAt} (evaluated at ${req.context.timestamp})`,
    });
    return {
      decision: 'DENY',
      reason: `Denied: Agent identity '${req.subject.agentId}' expired`,
      evaluatedAt: new Date().toISOString(),
      trace,
    };
  }

  trace.push({
    step: 'Identity Validity Check',
    status: 'passed',
    details: `Agent '${req.subject.agentId}' (${req.subject.agentType}) valid until ${req.subject.expiresAt}`,
  });

  // Step 2: Explicit DENY rules
  for (const rule of policy.rules) {
    if (rule.effect === 'DENY' && ruleMatches(rule, req)) {
      trace.push({
        step: `Evaluate Deny Rule: ${rule.id}`,
        status: 'triggered',
        details: rule.description || `Triggered explicit DENY rule: ${rule.id}`,
      });
      return {
        decision: 'DENY',
        reason: rule.description || `Denied by explicit rule: ${rule.id}`,
        matchedPolicyName: policy.name,
        matchedRuleId: rule.id,
        evaluatedAt: new Date().toISOString(),
        trace,
      };
    }
  }

  trace.push({
    step: 'Explicit DENY Rules Evaluation',
    status: 'passed',
    details: 'No explicit DENY rules matched the request context.',
  });

  // Step 3: APPROVAL_REQUIRED rules
  for (const rule of policy.rules) {
    if (rule.effect === 'APPROVAL_REQUIRED' && ruleMatches(rule, req)) {
      trace.push({
        step: `Evaluate Approval Rule: ${rule.id}`,
        status: 'triggered',
        details: rule.description || `Action requires human/quorum approval: ${rule.id}`,
      });
      return {
        decision: 'APPROVAL_REQUIRED',
        reason: rule.description || `Action requires human approval: ${rule.id}`,
        matchedPolicyName: policy.name,
        matchedRuleId: rule.id,
        evaluatedAt: new Date().toISOString(),
        trace,
      };
    }
  }

  trace.push({
    step: 'Approval Rules Evaluation',
    status: 'passed',
    details: 'No APPROVAL_REQUIRED conditions triggered.',
  });

  // Step 4: Explicit ALLOW rules
  for (const rule of policy.rules) {
    if (rule.effect === 'ALLOW' && ruleMatches(rule, req)) {
      trace.push({
        step: `Evaluate Allow Rule: ${rule.id}`,
        status: 'triggered',
        details: rule.description || `Permitted by explicit rule: ${rule.id}`,
      });
      return {
        decision: 'ALLOW',
        reason: rule.description || `Permitted by rule: ${rule.id}`,
        matchedPolicyName: policy.name,
        matchedRuleId: rule.id,
        evaluatedAt: new Date().toISOString(),
        trace,
      };
    }
  }

  // Step 5: RBAC Role & Permission evaluation
  const effectivePermissions = new Set<string>(req.subject.permissions || []);
  for (const roleName of req.subject.roles) {
    const roleDef = policy.roles[roleName];
    if (roleDef) {
      roleDef.permissions.forEach(p => effectivePermissions.add(p));
    }
  }

  let matchedPattern: string | null = null;
  for (const perm of effectivePermissions) {
    if (matchPermission(perm, req.action.name)) {
      matchedPattern = perm;
      break;
    }
  }

  if (matchedPattern) {
    trace.push({
      step: 'RBAC Permission Match',
      status: 'passed',
      details: `Action '${req.action.name}' matches granted permission pattern '${matchedPattern}' via roles [${req.subject.roles.join(', ')}]`,
    });
    return {
      decision: 'ALLOW',
      reason: `Permitted by permission pattern '${matchedPattern}'`,
      matchedPolicyName: policy.name,
      evaluatedAt: new Date().toISOString(),
      trace,
    };
  }

  // Step 6: Deny by default
  trace.push({
    step: 'Deny By Default Resolution',
    status: 'failed',
    details: `No permission pattern in [${Array.from(effectivePermissions).join(', ')}] satisfies action '${req.action.name}'`,
  });

  return {
    decision: 'DENY',
    reason: `Access denied: No matching permission or policy rule permits action '${req.action.name}' for agent '${req.subject.agentId}'`,
    matchedPolicyName: policy.name,
    evaluatedAt: new Date().toISOString(),
    trace,
  };
}

function ruleMatches(rule: PolicyRuleDef, req: AuthorizationRequest): boolean {
  if (rule.targetRoles && rule.targetRoles.length > 0) {
    const hasRole = req.subject.roles.some(r => rule.targetRoles!.includes(r));
    if (!hasRole) return false;
  }

  if (rule.targetActions && rule.targetActions.length > 0) {
    const hasAction = rule.targetActions.some(actPattern => matchPermission(actPattern, req.action.name));
    if (!hasAction) return false;
  }

  if (rule.resourceType && rule.resourceType.toLowerCase() !== req.resource.type.toLowerCase()) {
    return false;
  }

  if (rule.resourceId && rule.resourceId !== req.resource.id) {
    return false;
  }

  if (rule.environments && rule.environments.length > 0) {
    const matchesEnv = rule.environments.some(env => env.toLowerCase() === req.context.environment.toLowerCase());
    if (!matchesEnv) return false;
  }

  return true;
}
