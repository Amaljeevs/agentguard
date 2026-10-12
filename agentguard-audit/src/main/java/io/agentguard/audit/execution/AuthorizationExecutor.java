package io.agentguard.audit.execution;

import io.agentguard.audit.model.AuditEvent;
import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.exception.AgentApprovalRequiredException;
import io.agentguard.core.model.AuthorizationRequest;
import java.util.Map;
import java.util.Optional;
import io.agentguard.core.model.AuthorizationDecision;

import io.agentguard.core.metrics.AgentGuardMetrics;
import java.time.Duration;

/** Enforcement shared by Spring AOP and tool callbacks, including execution outcome events. */
public final class AuthorizationExecutor {
    private final PolicyEngine engine;
    private final AuditEventPublisher publisher;
    private final ParameterSanitizer sanitizer;
    private final ApprovalRequestHandler approvalHandler;
    private final AgentGuardMetrics metrics;

    public AuthorizationExecutor(PolicyEngine engine, AuditEventPublisher publisher, ParameterSanitizer sanitizer) {
        this(engine, publisher, sanitizer, (request, decision) -> Optional.empty(), AgentGuardMetrics.NOOP);
    }

    public AuthorizationExecutor(PolicyEngine engine, AuditEventPublisher publisher, ParameterSanitizer sanitizer,
                                 ApprovalRequestHandler approvalHandler) {
        this(engine, publisher, sanitizer, approvalHandler, AgentGuardMetrics.NOOP);
    }

    public AuthorizationExecutor(PolicyEngine engine, AuditEventPublisher publisher, ParameterSanitizer sanitizer,
                                 ApprovalRequestHandler approvalHandler, AgentGuardMetrics metrics) {
        this.engine = java.util.Objects.requireNonNull(engine);
        this.publisher = java.util.Objects.requireNonNull(publisher);
        this.sanitizer = java.util.Objects.requireNonNull(sanitizer);
        this.approvalHandler = java.util.Objects.requireNonNull(approvalHandler);
        this.metrics = metrics != null ? metrics : AgentGuardMetrics.NOOP;
    }

    @FunctionalInterface public interface Operation<T> { T execute() throws Throwable; }
    @FunctionalInterface public interface ApprovalRequestHandler {
        Optional<String> requestApproval(AuthorizationRequest request, AuthorizationDecision decision);
    }

    public <T> T execute(AuthorizationRequest request, Operation<T> operation) throws Throwable {
        String revision = engine.revision();
        long start = System.nanoTime();
        var decision = engine.evaluate(request);
        long elapsed = System.nanoTime() - start;
        metrics.recordDecision(decision.decision(), decision.riskLevel(), Duration.ofNanos(elapsed));
        var snapshot = AuditEvent.from(request, decision, sanitizer);
        String correlation = decision.traceId();
        publisher.publish(snapshot.lifecycle("AUTHORIZATION", correlation, revision, Map.of()));
        if (decision.isDenied()) {
            metrics.recordError("access_denied");
            throw new AgentAccessDeniedException("AgentGuard DENIED: " + decision.reason()
                + decision.matchedRuleId().map(id -> " [rule: " + id + "]").orElse(""), decision);
        }
        if (decision.isApprovalRequired()) {
            metrics.recordApprovalEvent("created");
            Optional<String> approvalId = approvalHandler.requestApproval(request, decision);
            throw new AgentApprovalRequiredException("AgentGuard APPROVAL_REQUIRED: " + decision.reason()
                + decision.matchedRuleId().map(id -> " [rule: " + id + "]").orElse("")
                + approvalId.map(id -> " [approval: " + id + "]").orElse(""), decision, approvalId);
        }
        T result;
        try { result = operation.execute(); }
        catch (Throwable failure) {
            metrics.recordError("execution_failure");
            try { publisher.publish(snapshot.lifecycle("EXECUTION_FAILED", correlation, revision,
                Map.of("exceptionType", failure.getClass().getName()))); }
            catch (RuntimeException auditFailure) { failure.addSuppressed(auditFailure); }
            throw failure;
        }
        publisher.publish(snapshot.lifecycle("EXECUTION_SUCCEEDED", correlation, revision, Map.of()));
        return result;
    }
}
