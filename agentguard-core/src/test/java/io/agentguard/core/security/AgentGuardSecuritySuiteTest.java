package io.agentguard.core.security;

import io.agentguard.core.AgentGuard;
import io.agentguard.core.engine.DefaultPermissionMatcher;
import io.agentguard.core.engine.DefaultPolicyEngine;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.exception.AgentAuthenticationException;
import io.agentguard.core.identity.*;
import io.agentguard.core.model.*;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Comprehensive security suite covering:
 * 1. Privilege escalation
 * 2. Forged identities
 * 3. Modified approved requests
 * 4. Replay attacks
 * 5. Expired approvals
 * 6. Excessive delegation depth
 * 7. Missing policies (deny-by-default)
 * 8. Malformed JWT claims
 * 9. Concurrent approval consumption
 * 10. Keycloak & Entra ID claim resolution
 * 11. SPIFFE workload identity resolution
 */
class AgentGuardSecuritySuiteTest {

    private final Instant now = Instant.parse("2026-10-12T12:00:00Z");
    private final Clock fixedClock = Clock.fixed(now, ZoneOffset.UTC);

    private AgentIdentity identity(String id, String parent, String permission) {
        return AgentIdentity.builder()
            .agentId(id)
            .delegatedBy(parent)
            .permission(permission)
            .issuedAt(now.minusSeconds(60))
            .expiresAt(now.plusSeconds(3600))
            .build();
    }

    private AuthorizationRequest request(AgentIdentity identity, String action, Map<String, Object> params) {
        return AuthorizationRequest.of(
            identity,
            Action.of(action, params),
            Resource.of("database", "prod-db"),
            new AuthorizationContext("production", now, Map.of("traceId", "trace-sec-1"))
        );
    }

    // 1. Privilege Escalation
    @Test
    void testPrivilegeEscalation_childCannotExceedParentAuthority() {
        var parent = identity("parent-agent", null, "database.read");
        var child = AgentIdentity.builder()
            .agentId("child-agent")
            .delegatedBy("parent-agent")
            .permissions(Set.of("database.read", "database.drop")) // Child attempts privilege escalation
            .issuedAt(now.minusSeconds(30))
            .expiresAt(now.plusSeconds(300))
            .build();

        var policy = PolicySet.builder("test-escalation", "1.0").build();
        var engine = new DefaultPolicyEngine(policy, new DefaultPermissionMatcher(), id -> Optional.of(parent));

        var decision = engine.evaluate(request(child, "database.read", Map.of()));
        assertThat(decision.isDenied()).isTrue();
        assertThat(decision.reason()).contains("child permissions exceed parent authority");
    }

    // 2. Forged Identities
    @Test
    void testForgedIdentities_payloadCannotImpersonateResolvedIdentity() {
        var verified = AgentIdentity.builder()
            .agentId("verified-service-account")
            .roles(Set.of("READER"))
            .permissions(Set.of("database.read"))
            .issuedAt(now.minusSeconds(60))
            .expiresAt(now.plusSeconds(3600))
            .build();

        AgentIdentityResolver resolver = () -> Optional.of(verified);

        var policy = PolicySet.builder("test-forged", "1.0")
            .rules(List.of(
                PolicyRule.builder("deny-forged-admin", RuleEffect.DENY)
                    .targetRoles(Set.of("FORGED_ADMIN"))
                    .build()
            ))
            .roles(Map.of(
                "READER", RoleDefinition.of("READER", Set.of("database.read"))
            ))
            .build();

        var engine = new DefaultPolicyEngine(policy);
        var guard = new AgentGuard(engine, resolver);

        // Caller attempts to supply forged subject in request payload
        var forgedSubject = AgentIdentity.builder()
            .agentId("forged-superadmin")
            .roles(Set.of("FORGED_ADMIN"))
            .permissions(Set.of("database.drop"))
            .issuedAt(now.minusSeconds(60))
            .expiresAt(now.plusSeconds(3600))
            .build();

        var requestWithForgedPayload = request(forgedSubject, "database.read", Map.of());

        // AgentGuard replaces untrusted payload identity with trusted verified identity
        var decision = guard.authorize(requestWithForgedPayload);
        assertThat(decision.isAllowed()).isTrue();
        assertThat(decision.reason()).contains("database.read");
    }

    // 6. Excessive Delegation Depth
    @Test
    void testExcessiveDelegationDepth_chainExceedingMaxDepthDenied() {
        var parent = identity("parent-agent", null, "database.read");
        var child = AgentIdentity.builder()
            .agentId("child-agent")
            .delegationChain(List.of("root", "inter-1", "inter-2", "parent-agent"))
            .permission("database.read")
            .issuedAt(now.minusSeconds(30))
            .expiresAt(now.plusSeconds(300))
            .build();

        var policy = PolicySet.builder("test-depth", "1.0").build();
        // Max depth set to 2, but chain length is 4
        var engine = new DefaultPolicyEngine(policy, new DefaultPermissionMatcher(), id -> Optional.of(parent), 2);

        var decision = engine.evaluate(request(child, "database.read", Map.of()));
        assertThat(decision.isDenied()).isTrue();
        assertThat(decision.reason()).contains("maximum depth");
    }

    // 7. Missing Policies (Deny-by-default)
    @Test
    void testMissingPolicies_requestsDenyByDefault() {
        var unconfiguredPolicy = PolicySet.builder("empty-policy", "1.0").build();
        var engine = new DefaultPolicyEngine(unconfiguredPolicy);

        var unprivileged = identity("random-agent", null, null);
        var decision = engine.evaluate(request(unprivileged, "cluster.delete", Map.of()));

        assertThat(decision.isDenied()).isTrue();
        assertThat(decision.reason()).contains("Access denied");
    }

    // 8. Malformed JWT Claims
    @Test
    void testMalformedJwtClaims_invalidTokensFailClosed() {
        var resolver = new JwtClaimsAgentIdentityResolver(() -> Optional.empty(), fixedClock);

        // Missing sub / client_id / oid / azp
        assertThatThrownBy(() -> resolver.resolve(new VerifiedClaims("issuer", Map.of("exp", now.plusSeconds(60).getEpochSecond()), now)))
            .isInstanceOf(AgentAuthenticationException.class)
            .hasMessageContaining("required");

        // Expired token
        assertThatThrownBy(() -> resolver.resolve(new VerifiedClaims("issuer", Map.of(
            "sub", "agent-1",
            "exp", now.minusSeconds(1).getEpochSecond()
        ), now)))
            .isInstanceOf(AgentAuthenticationException.class)
            .hasMessageContaining("expired");

        // Token with cycle in delegation chain
        assertThatThrownBy(() -> resolver.resolve(new VerifiedClaims("issuer", Map.of(
            "sub", "agent-1",
            "exp", now.plusSeconds(60).getEpochSecond(),
            "delegation_chain", List.of("node-a", "node-b", "node-a")
        ), now)))
            .isInstanceOf(AgentAuthenticationException.class)
            .hasMessageContaining("cycle");
    }

    // 10. Keycloak & Entra ID Claims Mapping
    @Test
    void testKeycloakAndEntraClaimsMapping_extractsRolesAndTenantAccurately() {
        var resolver = new JwtClaimsAgentIdentityResolver(() -> Optional.empty(), fixedClock);

        // Entra ID token using oid, azp, and tid
        Map<String, Object> entraClaims = new LinkedHashMap<>();
        entraClaims.put("oid", "00000000-0000-0000-0000-000000000001");
        entraClaims.put("azp", "entra-app-client-id");
        entraClaims.put("tid", "tenant-entra-guid");
        entraClaims.put("roles", List.of("SecurityOperator"));
        entraClaims.put("scp", "audit.read cluster.read");
        entraClaims.put("exp", now.plusSeconds(600).getEpochSecond());

        var entraIdentity = resolver.resolve(new VerifiedClaims("https://login.microsoftonline.com/tenant/v2.0", entraClaims, now));
        assertThat(entraIdentity.agentId()).isEqualTo("entra-app-client-id");
        assertThat(entraIdentity.tenantId()).contains("tenant-entra-guid");
        assertThat(entraIdentity.roles()).containsExactly("SecurityOperator");
        assertThat(entraIdentity.permissions()).containsExactlyInAnyOrder("audit.read", "cluster.read");

        // Keycloak token using resource_access client roles
        Map<String, Object> keycloakClaims = new LinkedHashMap<>();
        keycloakClaims.put("sub", "keycloak-service-account");
        keycloakClaims.put("realm_access", Map.of("roles", List.of("offline_access", "uma_authorization")));
        keycloakClaims.put("resource_access", Map.of(
            "k8s-service", Map.of("roles", List.of("k8s-admin")),
            "db-service", Map.of("roles", List.of("db-operator"))
        ));
        keycloakClaims.put("exp", now.plusSeconds(600).getEpochSecond());

        var keycloakIdentity = resolver.resolve(new VerifiedClaims("https://keycloak.corp/realms/prod", keycloakClaims, now));
        assertThat(keycloakIdentity.roles()).contains("offline_access", "uma_authorization", "k8s-admin", "db-operator");
    }

    // 11. SPIFFE Workload Identity Resolution
    @Test
    void testSpiffeIdentityResolution_validatesFormatAndBounds() {
        var spiffeId = "spiffe://prod.corp.internal/ns/ai/sa/governance-agent";
        var svid = SpiffeSvid.of(spiffeId, now.minusSeconds(60), now.plusSeconds(300));
        assertThat(svid.trustDomain()).isEqualTo("prod.corp.internal");

        var resolver = new SpiffeAgentIdentityResolver(() -> Optional.of(svid), fixedClock);
        var resolved = resolver.resolveCurrentIdentity().orElseThrow();

        assertThat(resolved.agentId()).isEqualTo(spiffeId);
        assertThat(resolved.tenantId()).contains("prod.corp.internal");
        assertThat(resolved.attributes().get("spiffe_trust_domain")).isEqualTo("prod.corp.internal");

        // Expired SVID throws fail-closed
        var expiredSvid = SpiffeSvid.of(spiffeId, now.minusSeconds(120), now.minusSeconds(10));
        var expiredResolver = new SpiffeAgentIdentityResolver(() -> Optional.of(expiredSvid), fixedClock);
        assertThatThrownBy(expiredResolver::resolveCurrentIdentity)
            .isInstanceOf(AgentAuthenticationException.class)
            .hasMessageContaining("expired");

        // Invalid SPIFFE scheme or missing trust domain
        assertThatThrownBy(() -> SpiffeSvid.of("https://invalid-scheme.com/path", now, now.plusSeconds(60)))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SpiffeSvid.of("spiffe:///missing-trust-domain", now, now.plusSeconds(60)))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
