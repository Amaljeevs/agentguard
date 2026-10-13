package io.agentguard.core.engine;

import io.agentguard.core.model.*;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.*;
import static org.assertj.core.api.Assertions.assertThat;

class PolicyHardeningTest {
    private final Instant now = Instant.parse("2026-01-01T12:00:00Z");
    private AgentIdentity identity(String id, String parent, String permission) {
        return AgentIdentity.builder().agentId(id).delegatedBy(parent).permission(permission)
            .issuedAt(now.minusSeconds(60)).expiresAt(now.plusSeconds(60)).build();
    }
    private AuthorizationRequest request(AgentIdentity identity) {
        return AuthorizationRequest.of(identity, Action.of("orders.refund"), Resource.of("order", "1"),
            new AuthorizationContext("production", now, Map.of()));
    }
    private PolicySet policy() {
        return PolicySet.builder("test", "1.0").rules(List.of(PolicyRule.builder("review", RuleEffect.APPROVAL_REQUIRED)
            .targetActions(Set.of("orders.refund")).build())).build();
    }
    @Test void approvalRequiresUnderlyingPermission() {
        var engine = new DefaultPolicyEngine(policy());
        assertThat(engine.evaluate(request(identity("child", null, null))).isDenied()).isTrue();
        assertThat(engine.evaluate(request(identity("child", null, "orders.*"))).isApprovalRequired()).isTrue();
    }
    @Test void delegatedCallRequiresEveryAncestorPermission() {
        var parent = identity("parent", null, "orders.read");
        var engine = new DefaultPolicyEngine(policy(), new DefaultPermissionMatcher(), id -> Optional.of(parent));
        assertThat(engine.evaluate(request(identity("child", "parent", "*"))).isDenied()).isTrue();
    }
    @Test void validDelegationStillRequiresApproval() {
        var parent = identity("parent", null, "orders.*");
        var engine = new DefaultPolicyEngine(policy(), new DefaultPermissionMatcher(), id -> Optional.of(parent));
        assertThat(engine.evaluate(request(identity("child", "parent", "orders.refund"))).isApprovalRequired()).isTrue();
    }
    @Test void unknownParentAndCyclesAreDenied() {
        assertThat(new DefaultPolicyEngine(policy()).evaluate(request(identity("child", "missing", "*"))).isDenied()).isTrue();
        var child = identity("child", "parent", "*");
        var parent = identity("parent", "child", "*");
        var identities = Map.of("child", child, "parent", parent);
        var engine = new DefaultPolicyEngine(policy(), new DefaultPermissionMatcher(), id -> Optional.ofNullable(identities.get(id)));
        assertThat(engine.evaluate(request(child)).isDenied()).isTrue();
    }
    @Test void expiryBoundaryAndNotYetValidIdentitiesAreDenied() {
        var engine = new DefaultPolicyEngine(policy());
        var expired = AgentIdentity.builder().agentId("expired").permission("*").issuedAt(now.minusSeconds(60)).expiresAt(now).build();
        var future = AgentIdentity.builder().agentId("future").permission("*").issuedAt(now.plusSeconds(60)).expiresAt(now.plusSeconds(120)).build();
        assertThat(engine.evaluate(request(expired)).isDenied()).isTrue();
        assertThat(engine.evaluate(request(future)).isDenied()).isTrue();
    }
    @Test void childCannotOutliveParent() {
        var parent = AgentIdentity.builder().agentId("parent").permission("*").issuedAt(now.minusSeconds(60)).expiresAt(now.plusSeconds(10)).build();
        var engine = new DefaultPolicyEngine(policy(), new DefaultPermissionMatcher(), id -> Optional.of(parent));
        assertThat(engine.evaluate(request(identity("child", "parent", "*"))).isDenied()).isTrue();
    }
    @Test void fingerprintChangesWithPolicyContentsButNotSetOrdering() {
        var a = PolicySet.builder("test", "1.0").roles(Map.of("role", RoleDefinition.of("role", new LinkedHashSet<>(List.of("a", "b"))))).build();
        var b = PolicySet.builder("test", "1.0").roles(Map.of("role", RoleDefinition.of("role", new LinkedHashSet<>(List.of("b", "a"))))).build();
        assertThat(PolicyRevision.of(a)).isEqualTo(PolicyRevision.of(b)).isNotEqualTo(PolicyRevision.of(policy()));
    }
    @Test void childCannotHoldAnyPermissionOutsideParentAuthority() {
        var parent = identity("parent", null, "orders.*");
        var child = AgentIdentity.builder().agentId("child").delegatedBy("parent")
            .permissions(Set.of("orders.refund", "secrets.read"))
            .issuedAt(now.minusSeconds(60)).expiresAt(now.plusSeconds(60)).build();
        var engine = new DefaultPolicyEngine(policy(), new DefaultPermissionMatcher(), id -> Optional.of(parent));
        assertThat(engine.evaluate(request(child)).reason()).contains("exceed parent authority");
    }
    @Test void configuredDelegationDepthAndClaimedAncestryAreEnforced() {
        var parent = identity("parent", null, "orders.*");
        var child = AgentIdentity.builder().agentId("child").permission("orders.refund")
            .delegationChain(List.of("root", "parent"))
            .issuedAt(now.minusSeconds(60)).expiresAt(now.plusSeconds(60)).build();
        var engine = new DefaultPolicyEngine(policy(), new DefaultPermissionMatcher(), id -> Optional.of(parent), 1);
        assertThat(engine.evaluate(request(child)).reason()).contains("maximum depth");
    }
    @Test void decisionsAreDeterministicWhenTimestampAndTraceAreSupplied() {
        var context = new AuthorizationContext("production", now, Map.of("traceId", "trace-fixed"));
        var request = AuthorizationRequest.of(identity("agent", null, "orders.refund"), Action.of("orders.refund"),
            Resource.of("order", "1"), context);
        var engine = new DefaultPolicyEngine(policy());
        assertThat(engine.evaluate(request)).isEqualTo(engine.evaluate(request));
        assertThat(engine.evaluate(request).policyHash()).contains(engine.revision());
        assertThat(engine.evaluate(request).riskLevel()).isEqualTo(RiskLevel.HIGH);
    }

    @Test void crossTenantDelegationIsDenied() {
        var parent = AgentIdentity.builder().agentId("parent").permission("orders.*")
            .issuedAt(now.minusSeconds(60)).expiresAt(now.plusSeconds(60))
            .attributes(Map.of("tenant", "tenant-alpha")).build();
        var child = AgentIdentity.builder().agentId("child").delegatedBy("parent").permission("orders.refund")
            .issuedAt(now.minusSeconds(60)).expiresAt(now.plusSeconds(60))
            .attributes(Map.of("tenant", "tenant-beta")).build();
        var engine = new DefaultPolicyEngine(policy(), new DefaultPermissionMatcher(), id -> Optional.of(parent));
        var decision = engine.evaluate(request(child));
        assertThat(decision.isDenied()).isTrue();
        assertThat(decision.reason()).contains("child tenant does not match parent tenant");
    }
}
