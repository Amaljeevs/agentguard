package io.agentguard.audit.execution;

import io.agentguard.audit.model.AuditEvent;
import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.exception.AgentApprovalRequiredException;
import io.agentguard.core.model.AuthorizationRequest;
import java.util.Map;
import java.util.UUID;

/** Enforcement shared by Spring AOP and tool callbacks, including execution outcome events. */
public final class AuthorizationExecutor {
    private final PolicyEngine engine;
    private final AuditEventPublisher publisher;
    private final ParameterSanitizer sanitizer;
    public AuthorizationExecutor(PolicyEngine engine, AuditEventPublisher publisher, ParameterSanitizer sanitizer) {
        this.engine = java.util.Objects.requireNonNull(engine);
        this.publisher = java.util.Objects.requireNonNull(publisher);
        this.sanitizer = java.util.Objects.requireNonNull(sanitizer);
    }
    @FunctionalInterface public interface Operation<T> { T execute() throws Throwable; }

    public <T> T execute(AuthorizationRequest request, Operation<T> operation) throws Throwable {
        String revision = engine.revision();
        var decision = engine.evaluate(request);
        var snapshot = AuditEvent.from(request, decision, sanitizer);
        String correlation = UUID.randomUUID().toString();
        publisher.publish(snapshot.lifecycle("AUTHORIZATION", correlation, revision, Map.of()));
        if (decision.isDenied()) throw new AgentAccessDeniedException("AgentGuard DENIED: " + decision.reason()
            + decision.matchedRuleId().map(id -> " [rule: " + id + "]").orElse(""), decision);
        if (decision.isApprovalRequired()) throw new AgentApprovalRequiredException("AgentGuard APPROVAL_REQUIRED: " + decision.reason()
            + decision.matchedRuleId().map(id -> " [rule: " + id + "]").orElse(""), decision);
        T result;
        try { result = operation.execute(); }
        catch (Throwable failure) {
            try { publisher.publish(snapshot.lifecycle("EXECUTION_FAILED", correlation, revision,
                Map.of("exceptionType", failure.getClass().getName()))); }
            catch (RuntimeException auditFailure) { failure.addSuppressed(auditFailure); }
            throw failure;
        }
        publisher.publish(snapshot.lifecycle("EXECUTION_SUCCEEDED", correlation, revision, Map.of()));
        return result;
    }
}
