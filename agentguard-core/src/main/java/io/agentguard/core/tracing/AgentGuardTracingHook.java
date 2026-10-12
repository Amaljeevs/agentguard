package io.agentguard.core.tracing;

import java.util.Optional;

/**
 * Pluggable, OpenTelemetry-compatible tracing hook for resolving the active distributed trace ID.
 * Decouples AgentGuard from specific distributed tracing vendors while preserving correlation.
 */
@FunctionalInterface
public interface AgentGuardTracingHook {

    Optional<String> resolveCurrentTraceId();

    AgentGuardTracingHook NOOP = Optional::empty;
}

