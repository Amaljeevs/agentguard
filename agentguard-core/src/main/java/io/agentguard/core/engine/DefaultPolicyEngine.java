package io.agentguard.core.engine;

import io.agentguard.core.model.Action;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.AuthorizationContext;
import io.agentguard.core.model.AuthorizationDecision;
import io.agentguard.core.model.AuthorizationRequest;
import io.agentguard.core.model.Decision;
import io.agentguard.core.model.PolicyRule;
import io.agentguard.core.model.PolicySet;
import io.agentguard.core.model.Resource;
import io.agentguard.core.model.RoleDefinition;
import io.agentguard.core.model.RuleEffect;
import io.agentguard.core.model.RiskLevel;
import io.agentguard.core.identity.AgentIdentityLookup;

import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.List;
import java.util.UUID;

/**
 * Standard implementation of {@link PolicyEngine}.
 * Enforces:
 * <ol>
 *   <li>Fail-closed identity validity and expiration checks</li>
 *   <li>Explicit DENY rules precedence over all ALLOW grants</li>
 *   <li>RBAC/explicit grants required before APPROVAL_REQUIRED evaluation</li>
 *   <li>Permission matching with hierarchical wildcards and trusted ancestry checks</li>
 *   <li>Contextual environment and resource matching</li>
 *   <li>Deny-by-default if no active rule or permission permits the action</li>
 * </ol>
 */
public class DefaultPolicyEngine implements PolicyEngine {

    private final PolicySet policySet;
    private final PermissionMatcher permissionMatcher;
    private final AgentIdentityLookup identities;
    private final String revision;
    private final int maxDelegationDepth;
    private final io.agentguard.core.tracing.AgentGuardTracingHook tracingHook;

    public DefaultPolicyEngine(PolicySet policySet) {
        this(policySet, new DefaultPermissionMatcher());
    }

    public DefaultPolicyEngine(PolicySet policySet, PermissionMatcher permissionMatcher) {
        this(policySet, permissionMatcher, id -> Optional.empty());
    }

    public DefaultPolicyEngine(PolicySet policySet, PermissionMatcher permissionMatcher, AgentIdentityLookup identities) {
        this(policySet, permissionMatcher, identities, 8);
    }

    public DefaultPolicyEngine(PolicySet policySet, PermissionMatcher permissionMatcher,
                               AgentIdentityLookup identities, int maxDelegationDepth) {
        this(policySet, permissionMatcher, identities, maxDelegationDepth, io.agentguard.core.tracing.AgentGuardTracingHook.NOOP);
    }

    public DefaultPolicyEngine(PolicySet policySet, PermissionMatcher permissionMatcher,
                               AgentIdentityLookup identities, int maxDelegationDepth,
                               io.agentguard.core.tracing.AgentGuardTracingHook tracingHook) {
        this.policySet = Objects.requireNonNull(policySet, "policySet must not be null");
        this.permissionMatcher = Objects.requireNonNull(permissionMatcher, "permissionMatcher must not be null");
        this.identities = Objects.requireNonNull(identities, "identities must not be null");
        if (maxDelegationDepth < 0 || maxDelegationDepth > 64) {
            throw new IllegalArgumentException("maxDelegationDepth must be between 0 and 64");
        }
        this.maxDelegationDepth = maxDelegationDepth;
        this.tracingHook = tracingHook != null ? tracingHook : io.agentguard.core.tracing.AgentGuardTracingHook.NOOP;
        this.revision = PolicyRevision.of(policySet);
    }

    @Override
    public String revision() { return revision; }

    @Override
    public AuthorizationDecision evaluate(AuthorizationRequest request) {
        Objects.requireNonNull(request, "AuthorizationRequest must not be null");
        String traceId = resolveTraceId(request.context());
        List<String> claimedChain = request.subject().delegationChain();
        if (claimedChain.size() > maxDelegationDepth) {
            return decision(Decision.DENY, "Invalid delegation: maximum depth exceeded", null,
                RiskLevel.HIGH, traceId, request.context().timestamp());
        }
        return evaluateChain(request, new HashSet<>(), claimedChain, traceId);
    }

    private AuthorizationDecision evaluateChain(AuthorizationRequest request, Set<String> visited,
                                                List<String> expectedChain, String traceId) {
        AgentIdentity subject = request.subject();
        AuthorizationDecision ownDecision = evaluateOwn(request, traceId);
        if (ownDecision.isDenied() || subject == null || subject.delegatedBy().isEmpty()) return ownDecision;
        if (visited.size() >= maxDelegationDepth || !visited.add(subject.agentId())) {
            return decision(Decision.DENY, "Invalid delegation: cycle or depth limit exceeded", null,
                RiskLevel.HIGH, traceId, request.context().timestamp());
        }
        String parentId = subject.delegatedBy().get();
        if (expectedChain.isEmpty() || !expectedChain.getLast().equals(parentId)) {
            return decision(Decision.DENY, "Invalid delegation: chain does not match immediate parent", null,
                RiskLevel.HIGH, traceId, request.context().timestamp());
        }
        Optional<AgentIdentity> parent;
        try { parent = identities.find(parentId); }
        catch (RuntimeException failure) {
            return decision(Decision.DENY, "Delegation parent lookup failed", null,
                RiskLevel.HIGH, traceId, request.context().timestamp());
        }
        if (parent == null || parent.isEmpty() || !parent.get().agentId().equals(parentId)) {
            return decision(Decision.DENY, "Delegation parent could not be verified", null,
                RiskLevel.HIGH, traceId, request.context().timestamp());
        }
        if (subject.issuedAt().isBefore(parent.get().issuedAt()) || subject.expiresAt().isAfter(parent.get().expiresAt())) {
            return decision(Decision.DENY, "Delegated identity validity must be within its parent's validity", null,
                RiskLevel.HIGH, traceId, request.context().timestamp());
        }
        List<String> parentChain = expectedChain.subList(0, expectedChain.size() - 1);
        if (!parent.get().delegationChain().equals(parentChain)) {
            return decision(Decision.DENY, "Invalid delegation: verified ancestry does not match claimed chain", null,
                RiskLevel.HIGH, traceId, request.context().timestamp());
        }
        if (!permissionsAreSubset(collectEffectivePermissions(subject), collectEffectivePermissions(parent.get()))) {
            return decision(Decision.DENY, "Invalid delegation: child permissions exceed parent authority", null,
                RiskLevel.CRITICAL, traceId, request.context().timestamp());
        }
        var parentDecision = evaluateChain(AuthorizationRequest.of(parent.get(), request.action(), request.resource(), request.context()),
            visited, parentChain, traceId);
        if (parentDecision.isDenied() || parentDecision.isApprovalRequired()) return parentDecision;
        return ownDecision;
    }

    private AuthorizationDecision evaluateOwn(AuthorizationRequest request, String traceId) {

        AgentIdentity subject = request.subject();
        Action action = request.action();
        Resource resource = request.resource();
        AuthorizationContext context = request.context();

        // 1. Identity validation & temporal boundary check
        if (subject == null) {
            return decision(Decision.DENY, "Denied: Subject agent identity is missing", null,
                RiskLevel.HIGH, traceId, context.timestamp());
        }

        Instant evalTime = context.timestamp() != null ? context.timestamp() : Instant.now();
        if (evalTime.isBefore(subject.issuedAt())) {
            return decision(Decision.DENY, "Denied: Agent identity is not yet valid", null,
                RiskLevel.HIGH, traceId, evalTime);
        }
        if (subject.isExpired(evalTime)) {
            return decision(Decision.DENY,
                String.format("Denied: Agent identity '%s' expired at %s (evaluated at %s)",
                    subject.agentId(), subject.expiresAt(), evalTime), null, RiskLevel.HIGH, traceId, evalTime);
        }

        // 2. Evaluate explicit DENY rules (Deny takes precedence over everything)
        for (PolicyRule rule : policySet.rules()) {
            if (rule.effect() == RuleEffect.DENY && matchesRule(rule, subject, action, resource, context)) {
                String reason = rule.description().orElse("Denied by explicit rule: " + rule.id());
                return decision(Decision.DENY, reason, rule, rule.risk(), traceId, evalTime);
            }
        }

        // Establish a grant before considering approval. Approval never creates permission.
        AuthorizationDecision grant = null;
        for (PolicyRule rule : policySet.rules()) {
            if (rule.effect() == RuleEffect.ALLOW && matchesRule(rule, subject, action, resource, context)) {
                String reason = rule.description().orElse("Permitted by rule: " + rule.id());
                grant = decision(Decision.ALLOW, reason, rule, rule.risk(), traceId, evalTime);
                break;
            }
        }

        // 5. Evaluate RBAC Permissions (subject explicit permissions + role permissions)
        Set<String> effectivePermissions = collectEffectivePermissions(subject);
        for (String grantedPattern : effectivePermissions.stream().sorted().toList()) {
            if (permissionMatcher.matches(grantedPattern, action.name())) {
                if (grant == null) grant = decision(Decision.ALLOW,
                    String.format("Permitted by role/identity permission pattern '%s'", grantedPattern),
                    null, RiskLevel.LOW, traceId, evalTime);
                break;
            }
        }

        if (grant != null) {
            for (PolicyRule rule : policySet.rules()) {
                if (rule.effect() == RuleEffect.APPROVAL_REQUIRED && matchesRule(rule, subject, action, resource, context)) {
                    return decision(Decision.APPROVAL_REQUIRED,
                        rule.description().orElse("Action requires approval: " + rule.id()),
                        rule, rule.risk(), traceId, evalTime);
                }
            }
            return grant;
        }
        // Deny by default
        return decision(Decision.DENY,
            String.format("Access denied: No matching permission or policy rule permits action '%s' for agent '%s'",
                action.name(), subject.agentId()), null, RiskLevel.MEDIUM, traceId, evalTime);
    }

    private boolean matchesRule(
        PolicyRule rule,
        AgentIdentity subject,
        Action action,
        Resource resource,
        AuthorizationContext context
    ) {
        // Target roles match: if rule specifies roles, agent must have at least one of them
        if (!rule.targetRoles().isEmpty()) {
            boolean hasMatchingRole = subject.roles().stream()
                .anyMatch(role -> rule.targetRoles().contains(role));
            if (!hasMatchingRole) {
                return false;
            }
        }

        // Target actions match: if rule specifies actions, action must match at least one pattern
        if (!rule.targetActions().isEmpty()) {
            boolean hasMatchingAction = rule.targetActions().stream()
                .anyMatch(pattern -> permissionMatcher.matches(pattern, action.name()));
            if (!hasMatchingAction) {
                return false;
            }
        }

        // Resource type match: if specified, must match resource.type()
        if (rule.resourceType().isPresent()) {
            if (!rule.resourceType().get().equalsIgnoreCase(resource.type())) {
                return false;
            }
        }

        // Resource id match: if specified, must match resource.id()
        if (rule.resourceId().isPresent()) {
            if (!rule.resourceId().get().equals(resource.id())) {
                return false;
            }
        }

        // Environment match: if rule specifies environment constraints, context must match
        if (!rule.environments().isEmpty()) {
            boolean matchesEnv = rule.environments().stream()
                .anyMatch(env -> env.equalsIgnoreCase(context.environment()));
            if (!matchesEnv) {
                return false;
            }
        }

        return true;
    }

    private Set<String> collectEffectivePermissions(AgentIdentity subject) {
        Set<String> permissions = new HashSet<>(subject.permissions());

        for (String roleName : subject.roles()) {
            Optional<RoleDefinition> roleDef = policySet.getRole(roleName);
            roleDef.ifPresent(def -> permissions.addAll(def.permissions()));
        }

        return permissions;
    }

    private boolean permissionsAreSubset(Set<String> child, Set<String> parent) {
        return child.stream().allMatch(childPermission -> parent.stream()
            .anyMatch(parentPermission -> permissionCovers(parentPermission, childPermission)));
    }

    /** Conservative wildcard containment: ambiguous patterns deny rather than widening authority. */
    private boolean permissionCovers(String parent, String child) {
        if (Objects.equals(parent, child) || "*".equals(parent)) return true;
        if (!child.contains("*")) return permissionMatcher.matches(parent, child);
        if (parent.endsWith("*") && parent.indexOf('*') == parent.length() - 1) {
            return child.startsWith(parent.substring(0, parent.length() - 1));
        }
        if (parent.startsWith("*") && parent.lastIndexOf('*') == 0) {
            return child.endsWith(parent.substring(1));
        }
        return false;
    }

    private AuthorizationDecision decision(Decision effect, String reason, PolicyRule rule, RiskLevel risk,
                                           String traceId, Instant evaluatedAt) {
        return AuthorizationDecision.detailed(effect, reason, policySet.policyId(), rule == null ? null : rule.id(),
            policySet.version(), revision, risk, traceId, evaluatedAt);
    }

    private String resolveTraceId(AuthorizationContext context) {
        Object supplied = context.metadata().get("traceId");
        if (supplied instanceof String trace && !trace.isBlank() && trace.length() <= 128) return trace;
        if (tracingHook != null) {
            java.util.Optional<String> hookTrace = tracingHook.resolveCurrentTraceId();
            if (hookTrace != null && hookTrace.isPresent() && !hookTrace.get().isBlank()) {
                return hookTrace.get();
            }
        }
        return UUID.randomUUID().toString();
    }

    public PolicySet getPolicySet() {
        return policySet;
    }
}
