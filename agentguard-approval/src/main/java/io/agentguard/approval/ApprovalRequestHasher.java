package io.agentguard.approval;

import io.agentguard.core.model.AuthorizationRequest;
import io.agentguard.core.security.RequestFingerprint;

/** Public approval-binding utility for persistent approval-store adapters. */
public final class ApprovalRequestHasher {
    private ApprovalRequestHasher() {}
    public static String sha256(AuthorizationRequest request) { return RequestFingerprint.requestHash(request); }
}
