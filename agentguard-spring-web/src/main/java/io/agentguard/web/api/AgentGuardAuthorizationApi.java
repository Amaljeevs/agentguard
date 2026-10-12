package io.agentguard.web.api;

import io.agentguard.approval.ApprovalService;
import io.agentguard.audit.model.AuditEvent;
import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.identity.AgentIdentityResolver;
import io.agentguard.core.model.*;
import java.time.Duration;
import java.util.*;

/** Protocol service behind the HTTP adapter; it never builds authority from request principal data. */
public final class AgentGuardAuthorizationApi {
    private final PolicyEngine engine;
    private final AgentIdentityResolver identities;
    private final AuditEventPublisher audit;
    private final ParameterSanitizer sanitizer;
    private final Optional<ApprovalService> approvals;
    private final Duration approvalTtl;

    private final io.agentguard.core.metrics.AgentGuardMetrics metrics;

    public AgentGuardAuthorizationApi(PolicyEngine engine, AgentIdentityResolver identities,
                                      AuditEventPublisher audit, ParameterSanitizer sanitizer) {
        this(engine, identities, audit, sanitizer, Optional.empty(), Duration.ofMinutes(5), io.agentguard.core.metrics.AgentGuardMetrics.NOOP);
    }

    public AgentGuardAuthorizationApi(PolicyEngine engine, AgentIdentityResolver identities,
                                      AuditEventPublisher audit, ParameterSanitizer sanitizer,
                                      Optional<ApprovalService> approvals, Duration approvalTtl) {
        this(engine, identities, audit, sanitizer, approvals, approvalTtl, io.agentguard.core.metrics.AgentGuardMetrics.NOOP);
    }

    public AgentGuardAuthorizationApi(PolicyEngine engine, AgentIdentityResolver identities,
                                      AuditEventPublisher audit, ParameterSanitizer sanitizer,
                                      Optional<ApprovalService> approvals, Duration approvalTtl,
                                      io.agentguard.core.metrics.AgentGuardMetrics metrics) {
        this.engine = Objects.requireNonNull(engine); this.identities = Objects.requireNonNull(identities);
        this.audit = Objects.requireNonNull(audit); this.sanitizer = Objects.requireNonNull(sanitizer);
        this.approvals = approvals == null ? Optional.empty() : approvals;
        this.approvalTtl = Objects.requireNonNull(approvalTtl);
        this.metrics = metrics != null ? metrics : io.agentguard.core.metrics.AgentGuardMetrics.NOOP;
    }

    public AuthorizationApiResponse authorize(AuthorizationApiRequest input) {
        Objects.requireNonNull(input, "input");
        AgentIdentity identity = identities.resolveCurrentIdentity()
            .orElseThrow(() -> {
                metrics.recordError("missing_identity");
                return new AgentAccessDeniedException("Authenticated agent identity is required");
            });
        if (input.principal() != null && !input.principal().isBlank() && !input.principal().equals(identity.agentId())) {
            metrics.recordError("principal_mismatch");
            throw new AgentAccessDeniedException("Request principal does not match the verified identity");
        }
        Object environmentValue = input.context().get("environment");
        if (!(environmentValue instanceof String environment) || environment.isBlank()) {
            metrics.recordError("invalid_environment");
            throw new IllegalArgumentException("context.environment is required");
        }
        Map<String, Object> metadata = new LinkedHashMap<>(input.context());
        metadata.remove("environment");
        var request = AuthorizationRequest.of(identity, Action.of(input.action(), input.arguments()),
            Resource.of(input.resource().type(), input.resource().id(), input.resource().tags()),
            AuthorizationContext.of(environment, metadata));
        long start = System.nanoTime();
        AuthorizationDecision decision = engine.evaluate(request);
        long elapsed = System.nanoTime() - start;
        metrics.recordDecision(decision.decision(), decision.riskLevel(), Duration.ofNanos(elapsed));
        audit.publish(AuditEvent.from(request, decision, sanitizer).lifecycle(
            "AUTHORIZATION", decision.traceId(), engine.revision(), Map.of("transport", "http")));
        String approvalId = null;
        if (decision.isApprovalRequired() && approvals.isPresent()) {
            approvalId = approvals.get().request(request, approvalTtl).id();
        }
        return new AuthorizationApiResponse(decision.decision(), decision.reason(),
            decision.matchedPolicyId().orElse(null), decision.matchedRuleId().orElse(null),
            decision.policyVersion().orElse(null), decision.policyHash().orElse(null), decision.riskLevel(),
            approvalId, decision.traceId());
    }
}
