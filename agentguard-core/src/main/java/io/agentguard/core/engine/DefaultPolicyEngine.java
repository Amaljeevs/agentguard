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
 *   <li>APPROVAL_REQUIRED evaluation for sensitive or high-risk actions</li>
 *   <li>RBAC permission matching with hierarchical wildcards</li>
 *   <li>Contextual environment and resource matching</li>
 *   <li>Deny-by-default if no active rule or permission permits the action</li>
 * </ol>
 */
public class DefaultPolicyEngine implements PolicyEngine {

    private final PolicySet policySet;
    private final PermissionMatcher permissionMatcher;

    public DefaultPolicyEngine(PolicySet policySet) {
        this(policySet, new DefaultPermissionMatcher());
    }

    public DefaultPolicyEngine(PolicySet policySet, PermissionMatcher permissionMatcher) {
        this.policySet = Objects.requireNonNull(policySet, "policySet must not be null");
        this.permissionMatcher = Objects.requireNonNull(permissionMatcher, "permissionMatcher must not be null");
    }

    @Override
    public AuthorizationDecision evaluate(AuthorizationRequest request) {
        Objects.requireNonNull(request, "AuthorizationRequest must not be null");

        AgentIdentity subject = request.subject();
        Action action = request.action();
        Resource resource = request.resource();
        AuthorizationContext context = request.context();

        // 1. Identity validation & temporal boundary check
        if (subject == null) {
            return AuthorizationDecision.deny("Denied: Subject agent identity is missing");
        }

        Instant evalTime = context.timestamp() != null ? context.timestamp() : Instant.now();
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

        // 3. Evaluate APPROVAL_REQUIRED rules
        for (PolicyRule rule : policySet.rules()) {
            if (rule.effect() == RuleEffect.APPROVAL_REQUIRED && matchesRule(rule, subject, action, resource, context)) {
                String reason = rule.description().orElse("Action requires human/quorum approval: " + rule.id());
                return AuthorizationDecision.requireApproval(reason, policySet.name(), rule.id());
            }
        }

        // 4. Evaluate explicit ALLOW rules
        for (PolicyRule rule : policySet.rules()) {
            if (rule.effect() == RuleEffect.ALLOW && matchesRule(rule, subject, action, resource, context)) {
                String reason = rule.description().orElse("Permitted by rule: " + rule.id());
                return AuthorizationDecision.allow(reason, policySet.name(), rule.id());
            }
        }

        // 5. Evaluate RBAC Permissions (subject explicit permissions + role permissions)
        Set<String> effectivePermissions = collectEffectivePermissions(subject);
        for (String grantedPattern : effectivePermissions) {
            if (permissionMatcher.matches(grantedPattern, action.name())) {
                return AuthorizationDecision.allow(
                    String.format("Permitted by role/identity permission pattern '%s'", grantedPattern),
                    policySet.name()
                );
            }
        }

        // 6. Deny by default
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
