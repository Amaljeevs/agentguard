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
import io.agentguard.core.identity.AgentIdentityLookup;

import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

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

    public DefaultPolicyEngine(PolicySet policySet) {
        this(policySet, new DefaultPermissionMatcher());
    }

    public DefaultPolicyEngine(PolicySet policySet, PermissionMatcher permissionMatcher) {
        this(policySet, permissionMatcher, id -> Optional.empty());
    }

    public DefaultPolicyEngine(PolicySet policySet, PermissionMatcher permissionMatcher, AgentIdentityLookup identities) {
        this.policySet = Objects.requireNonNull(policySet, "policySet must not be null");
        this.permissionMatcher = Objects.requireNonNull(permissionMatcher, "permissionMatcher must not be null");
        this.identities = Objects.requireNonNull(identities, "identities must not be null");
        this.revision = PolicyRevision.of(policySet);
    }

    @Override
    public String revision() { return revision; }

    @Override
    public AuthorizationDecision evaluate(AuthorizationRequest request) {
        Objects.requireNonNull(request, "AuthorizationRequest must not be null");
        return evaluateChain(request, new HashSet<>());
    }

    private AuthorizationDecision evaluateChain(AuthorizationRequest request, Set<String> visited) {
        AgentIdentity subject = request.subject();
        AuthorizationDecision ownDecision = evaluateOwn(request);
        if (ownDecision.isDenied() || subject == null || subject.delegatedBy().isEmpty()) return ownDecision;
        if (visited.size() >= 32 || !visited.add(subject.agentId())) {
            return AuthorizationDecision.deny("Invalid delegation: cycle or depth limit exceeded");
        }
        String parentId = subject.delegatedBy().get();
        Optional<AgentIdentity> parent;
        try { parent = identities.find(parentId); }
        catch (RuntimeException failure) { return AuthorizationDecision.deny("Delegation parent lookup failed"); }
        if (parent == null || parent.isEmpty() || !parent.get().agentId().equals(parentId)) {
            return AuthorizationDecision.deny("Delegation parent could not be verified");
        }
        if (subject.issuedAt().isBefore(parent.get().issuedAt()) || subject.expiresAt().isAfter(parent.get().expiresAt())) {
            return AuthorizationDecision.deny("Delegated identity validity must be within its parent's validity");
        }
        var parentDecision = evaluateChain(AuthorizationRequest.of(parent.get(), request.action(), request.resource(), request.context()), visited);
        if (parentDecision.isDenied() || parentDecision.isApprovalRequired()) return parentDecision;
        return ownDecision;
    }

    private AuthorizationDecision evaluateOwn(AuthorizationRequest request) {

        AgentIdentity subject = request.subject();
        Action action = request.action();
        Resource resource = request.resource();
        AuthorizationContext context = request.context();

        // 1. Identity validation & temporal boundary check
        if (subject == null) {
            return AuthorizationDecision.deny("Denied: Subject agent identity is missing");
        }

        Instant evalTime = context.timestamp() != null ? context.timestamp() : Instant.now();
        if (evalTime.isBefore(subject.issuedAt())) {
            return AuthorizationDecision.deny("Denied: Agent identity is not yet valid");
        }
        if (subject.isExpired(evalTime)) {
            return AuthorizationDecision.deny(
                String.format("Denied: Agent identity '%s' expired at %s (evaluated at %s)",
                    subject.agentId(), subject.expiresAt(), evalTime)
            );
        }

        // 2. Evaluate explicit DENY rules (Deny takes precedence over everything)
        for (PolicyRule rule : policySet.rules()) {
            if (rule.effect() == RuleEffect.DENY && matchesRule(rule, subject, action, resource, context)) {
                String reason = rule.description().orElse("Denied by explicit rule: " + rule.id());
                return AuthorizationDecision.deny(reason, policySet.name(), rule.id());
            }
        }

        // Establish a grant before considering approval. Approval never creates permission.
        AuthorizationDecision grant = null;
        for (PolicyRule rule : policySet.rules()) {
            if (rule.effect() == RuleEffect.ALLOW && matchesRule(rule, subject, action, resource, context)) {
                String reason = rule.description().orElse("Permitted by rule: " + rule.id());
                grant = AuthorizationDecision.allow(reason, policySet.name(), rule.id());
                break;
            }
        }

        // 5. Evaluate RBAC Permissions (subject explicit permissions + role permissions)
        Set<String> effectivePermissions = collectEffectivePermissions(subject);
        for (String grantedPattern : effectivePermissions.stream().sorted().toList()) {
            if (permissionMatcher.matches(grantedPattern, action.name())) {
                if (grant == null) grant = AuthorizationDecision.allow(
                    String.format("Permitted by role/identity permission pattern '%s'", grantedPattern),
                    policySet.name()
                );
                break;
            }
        }

        if (grant != null) {
            for (PolicyRule rule : policySet.rules()) {
                if (rule.effect() == RuleEffect.APPROVAL_REQUIRED && matchesRule(rule, subject, action, resource, context)) {
                    return AuthorizationDecision.requireApproval(rule.description().orElse("Action requires approval: " + rule.id()),
                        policySet.name(), rule.id());
                }
            }
            return grant;
        }
        // Deny by default
        return AuthorizationDecision.deny(
            String.format("Access denied: No matching permission or policy rule permits action '%s' for agent '%s'",
                action.name(), subject.agentId())
        );
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

    public PolicySet getPolicySet() {
        return policySet;
    }
}
