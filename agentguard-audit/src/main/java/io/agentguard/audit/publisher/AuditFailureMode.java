package io.agentguard.audit.publisher;

/** FAIL_CLOSED aborts the call on publisher failure; BEST_EFFORT continues and reports a safe warning. */
public enum AuditFailureMode { FAIL_CLOSED, BEST_EFFORT }
