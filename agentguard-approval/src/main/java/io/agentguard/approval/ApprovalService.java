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
import io.agentguard.core.security.RequestFingerprint;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Exact-request approvals. Authenticate requester/approver outside this service using trusted identity providers. */
public final class ApprovalService {
    private final PolicyEngine engine;
    private final ApprovalStore store;
    private final Clock clock;
    private final AuditEventPublisher audit;
    private final ParameterSanitizer sanitizer;
    private final io.agentguard.core.metrics.AgentGuardMetrics metrics;

    public ApprovalService(PolicyEngine engine, ApprovalStore store, Clock clock,
                           AuditEventPublisher audit, ParameterSanitizer sanitizer) {
        this(engine, store, clock, audit, sanitizer, io.agentguard.core.metrics.AgentGuardMetrics.NOOP);
    }

    public ApprovalService(PolicyEngine engine, ApprovalStore store, Clock clock,
                           AuditEventPublisher audit, ParameterSanitizer sanitizer,
                           io.agentguard.core.metrics.AgentGuardMetrics metrics) {
        this.engine = Objects.requireNonNull(engine); this.store = Objects.requireNonNull(store);
        this.clock = Objects.requireNonNull(clock); this.audit = Objects.requireNonNull(audit);
        this.sanitizer = Objects.requireNonNull(sanitizer);
        this.metrics = metrics != null ? metrics : io.agentguard.core.metrics.AgentGuardMetrics.NOOP;
    }

    public ApprovalTicket request(AuthorizationRequest request, Duration ttl) {
        if (ttl.isNegative() || ttl.isZero() || ttl.compareTo(Duration.ofHours(1)) > 0) throw new IllegalArgumentException("TTL must be within one hour");
        var snapshot = RequestBinding.snapshot(request, clock.instant());
        String revision = revision();
        var decision = engine.evaluate(snapshot);
        if (!decision.isApprovalRequired()) throw denied("Request is not eligible for approval");
        Instant expiry = clock.instant().plus(ttl);
        if (snapshot.subject().expiresAt().isBefore(expiry)) expiry = snapshot.subject().expiresAt();
        var ticket = new ApprovalTicket(UUID.randomUUID().toString(), snapshot.subject().agentId(), snapshot.action().name(),
            snapshot.resource().type(), snapshot.resource().id(), RequestBinding.digest(snapshot),
            RequestFingerprint.argumentsHash(snapshot.action().parameters()), revision, snapshot.context().environment(),
            decision.traceId(), clock.instant(), expiry, ApprovalTicket.State.APPROVAL_REQUIRED, null);
        audit.publish(AuditEvent.from(snapshot, decision, sanitizer).lifecycle("APPROVAL_REQUIRED", ticket.id(), revision,
            Map.of("approvalState", ticket.state().name())));
        store.create(ticket);
        metrics.recordApprovalEvent("created");
        return ticket;
    }

    public ApprovalTicket approve(String id, AgentIdentity approver) { return decide(id, approver, true); }
    public ApprovalTicket reject(String id, AgentIdentity approver) { return decide(id, approver, false); }

    private ApprovalTicket decide(String id, AgentIdentity approver, boolean approve) {
        var expired = new AtomicBoolean();
        var event = new AtomicReference<AuditEvent>();
        ApprovalTicket result = store.update(id, ticket -> {
            if (isAwaitingDecision(ticket.state()) && !clock.instant().isBefore(ticket.expiresAt())) {
                expired.set(true);
                return ticket.withState(ApprovalTicket.State.EXPIRED, null);
            }
            validate(ticket, ApprovalTicket.State.APPROVAL_REQUIRED);
            if (ticket.subjectId().equals(approver.agentId())) throw denied("Self approval is forbidden");
            var request = AuthorizationRequest.of(approver, Action.of("agentguard.approval.approve"),
                Resource.of("approval", id), AuthorizationContext.of(ticket.environment()));
            request = RequestBinding.snapshot(request, clock.instant());
            var decision = engine.evaluate(request);
            if (!decision.isAllowed()) throw denied("Approver is not authorized");
            event.set(AuditEvent.from(request, decision, sanitizer));
            ApprovalTicket next = ticket.withState(approve ? ApprovalTicket.State.APPROVED : ApprovalTicket.State.DENIED,
                approver.agentId());
            audit.publish(event.get().lifecycle(approve ? "APPROVAL_APPROVED" : "APPROVAL_DENIED", id,
                next.policyRevision(), Map.of("approvalState", next.state().name())));
            return next;
        });
        if (expired.get()) {
            metrics.recordApprovalEvent("expired");
            auditExpiry(approver, result);
            throw denied("Approval expired");
        }
        metrics.recordApprovalEvent(approve ? "approved" : "denied");
        return result;
    }

    public <T> T execute(String id, AuthorizationRequest request, Function<AuthorizationRequest, T> operation) {
        var snapshot = RequestBinding.snapshot(request, clock.instant());
        String binding = RequestBinding.digest(snapshot);
        // Freeze inputs for the callback; re-evaluate current rights immediately before atomic consumption.
        var decision = engine.evaluate(snapshot);
        if (decision.isDenied()) throw denied("Request no longer authorized");
        var event = AuditEvent.from(snapshot, decision, sanitizer);
        var expired = new AtomicBoolean();
        var ticket = store.update(id, current -> {
            if (current.state() == ApprovalTicket.State.APPROVED && !clock.instant().isBefore(current.expiresAt())) {
                expired.set(true);
                return current.withState(ApprovalTicket.State.EXPIRED, current.decidedBy());
            }
            validate(current, ApprovalTicket.State.APPROVED);
            if (!current.requestHash().equals(binding)) throw denied("Approval does not match this request");
            audit.publish(event.lifecycle("APPROVAL_CONSUMED", id, current.policyRevision(),
                Map.of("approvalState", ApprovalTicket.State.CONSUMED.name())));
            return current.withState(ApprovalTicket.State.CONSUMED, current.decidedBy());
        });
        if (expired.get()) {
            metrics.recordApprovalEvent("expired");
            audit.publish(event.lifecycle("APPROVAL_EXPIRED", id, ticket.policyRevision(),
                Map.of("approvalState", ApprovalTicket.State.EXPIRED.name())));
            throw denied("Approval expired");
        }
        metrics.recordApprovalEvent("consumed");
        T result;
        try { result = operation.apply(snapshot); }
        catch (RuntimeException | Error failure) {
            metrics.recordError("execution_failure");
            try { audit.publish(event.lifecycle("EXECUTION_FAILED", id, ticket.policyRevision(),
                Map.of("exceptionType", failure.getClass().getName(), "approvalRequestId", id))); }
            catch (RuntimeException auditFailure) { failure.addSuppressed(auditFailure); }
            throw failure;
        }
        audit.publish(event.lifecycle("EXECUTION_SUCCEEDED", id, ticket.policyRevision(), Map.of("approvalRequestId", id)));
        return result;
    }

    private void validate(ApprovalTicket ticket, ApprovalTicket.State expected) {
        if (expected == ApprovalTicket.State.APPROVAL_REQUIRED) {
            if (!isAwaitingDecision(ticket.state())) throw denied("Approval is not in the required state");
        } else if (ticket.state() != expected) throw denied("Approval is not in the required state");
        if (!ticket.policyRevision().equals(revision())) throw denied("Policy changed; request a new approval");
    }
    private String revision() {
        String revision = engine.revision();
        if (revision == null || revision.isBlank() || revision.equals("unversioned")) throw new IllegalStateException("Approvals require a versioned policy engine");
        return revision;
    }
    private static AgentAccessDeniedException denied(String message) { return new AgentAccessDeniedException(message); }
    @SuppressWarnings("deprecation")
    private static boolean isAwaitingDecision(ApprovalTicket.State state) {
        return state == ApprovalTicket.State.APPROVAL_REQUIRED || state == ApprovalTicket.State.PENDING;
    }

    private void auditExpiry(AgentIdentity actor, ApprovalTicket ticket) {
        var request = AuthorizationRequest.of(actor, Action.of("agentguard.approval.approve"),
            Resource.of("approval", ticket.id()), AuthorizationContext.of(ticket.environment()));
        var decision = AuthorizationDecision.deny("Approval expired");
        audit.publish(AuditEvent.from(request, decision, sanitizer).lifecycle("APPROVAL_EXPIRED", ticket.id(),
            ticket.policyRevision(), Map.of("approvalState", ApprovalTicket.State.EXPIRED.name())));
    }
}
