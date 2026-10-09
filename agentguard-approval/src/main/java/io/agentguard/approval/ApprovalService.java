package io.agentguard.approval;

import io.agentguard.audit.model.AuditEvent;
import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.model.*;
import java.time.*;
import java.util.*;
import java.util.function.Function;

/** Exact-request approvals. Authenticate requester/approver outside this service using trusted identity providers. */
public final class ApprovalService {
    private final PolicyEngine engine;
    private final ApprovalStore store;
    private final Clock clock;
    private final AuditEventPublisher audit;
    private final ParameterSanitizer sanitizer;

    public ApprovalService(PolicyEngine engine, ApprovalStore store, Clock clock,
                           AuditEventPublisher audit, ParameterSanitizer sanitizer) {
        this.engine = Objects.requireNonNull(engine); this.store = Objects.requireNonNull(store);
        this.clock = Objects.requireNonNull(clock); this.audit = Objects.requireNonNull(audit);
        this.sanitizer = Objects.requireNonNull(sanitizer);
    }

    public ApprovalTicket request(AuthorizationRequest request, Duration ttl) {
        if (ttl.isNegative() || ttl.isZero() || ttl.compareTo(Duration.ofHours(1)) > 0) throw new IllegalArgumentException("TTL must be within one hour");
        var snapshot = RequestBinding.snapshot(request, clock.instant());
        String revision = revision();
        var decision = engine.evaluate(snapshot);
        if (!decision.isApprovalRequired()) throw denied("Request is not eligible for approval");
        Instant expiry = clock.instant().plus(ttl);
        if (snapshot.subject().expiresAt().isBefore(expiry)) expiry = snapshot.subject().expiresAt();
        var ticket = new ApprovalTicket(UUID.randomUUID().toString(), snapshot.subject().agentId(), RequestBinding.digest(snapshot),
            revision, snapshot.context().environment(), clock.instant(), expiry, ApprovalTicket.State.PENDING, null);
        audit.publish(AuditEvent.from(snapshot, decision, sanitizer).lifecycle("APPROVAL_REQUESTED", ticket.id(), revision, Map.of()));
        store.create(ticket);
        return ticket;
    }

    public ApprovalTicket approve(String id, AgentIdentity approver) { return decide(id, approver, true); }
    public ApprovalTicket reject(String id, AgentIdentity approver) { return decide(id, approver, false); }

    private ApprovalTicket decide(String id, AgentIdentity approver, boolean approve) {
        return store.update(id, ticket -> {
            validate(ticket, ApprovalTicket.State.PENDING);
            if (ticket.subjectId().equals(approver.agentId())) throw denied("Self approval is forbidden");
            var request = AuthorizationRequest.of(approver, Action.of("agentguard.approval.approve"),
                Resource.of("approval", id), AuthorizationContext.of(ticket.environment()));
            request = RequestBinding.snapshot(request, clock.instant());
            var decision = engine.evaluate(request);
            if (!decision.isAllowed()) throw denied("Approver is not authorized");
            audit.publish(AuditEvent.from(request, decision, sanitizer).lifecycle(
                approve ? "APPROVAL_GRANTED" : "APPROVAL_REJECTED", id, ticket.policyRevision(), Map.of()));
            return ticket.withState(approve ? ApprovalTicket.State.APPROVED : ApprovalTicket.State.REJECTED, approver.agentId());
        });
    }

    public <T> T execute(String id, AuthorizationRequest request, Function<AuthorizationRequest, T> operation) {
        var snapshot = RequestBinding.snapshot(request, clock.instant());
        String binding = RequestBinding.digest(snapshot);
        // Freeze inputs for the callback; re-evaluate current rights immediately before atomic consumption.
        var decision = engine.evaluate(snapshot);
        if (decision.isDenied()) throw denied("Request no longer authorized");
        var event = AuditEvent.from(snapshot, decision, sanitizer);
        var ticket = store.update(id, current -> {
            validate(current, ApprovalTicket.State.APPROVED);
            if (!current.binding().equals(binding)) throw denied("Approval does not match this request");
            audit.publish(event.lifecycle("APPROVAL_CONSUMED", id, current.policyRevision(), Map.of()));
            return current.withState(ApprovalTicket.State.CONSUMED, current.approvedBy());
        });
        T result;
        try { result = operation.apply(snapshot); }
        catch (RuntimeException | Error failure) {
            try { audit.publish(event.lifecycle("EXECUTION_FAILED", id, ticket.policyRevision(),
                Map.of("exceptionType", failure.getClass().getName()))); }
            catch (RuntimeException auditFailure) { failure.addSuppressed(auditFailure); }
            throw failure;
        }
        audit.publish(event.lifecycle("EXECUTION_SUCCEEDED", id, ticket.policyRevision(), Map.of()));
        return result;
    }

    private void validate(ApprovalTicket ticket, ApprovalTicket.State expected) {
        if (ticket.state() != expected) throw denied("Approval is not in the required state");
        if (!clock.instant().isBefore(ticket.expiresAt())) throw denied("Approval expired");
        if (!ticket.policyRevision().equals(revision())) throw denied("Policy changed; request a new approval");
    }
    private String revision() {
        String revision = engine.revision();
        if (revision == null || revision.isBlank() || revision.equals("unversioned")) throw new IllegalStateException("Approvals require a versioned policy engine");
        return revision;
    }
    private static AgentAccessDeniedException denied(String message) { return new AgentAccessDeniedException(message); }
}
