package io.agentguard.approval;

import java.util.Optional;
import java.util.function.UnaryOperator;

/** Implement update atomically across ALL callers/processes sharing the store. */
public interface ApprovalStore {
    void create(ApprovalTicket ticket);
    Optional<ApprovalTicket> find(String id);
    ApprovalTicket update(String id, UnaryOperator<ApprovalTicket> transition);
}
