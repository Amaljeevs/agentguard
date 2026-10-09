package io.agentguard.spring.ai;

import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.PolicyEngine;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;
import java.util.Arrays;

/** Registers only guarded callbacks, preserving tool schemas and metadata. */
public final class GuardedToolCallbackProvider implements ToolCallbackProvider {
    private final ToolCallback[] callbacks;
    public GuardedToolCallbackProvider(ToolCallbackProvider delegate, ToolAuthorizationResolver resolver,
                                       PolicyEngine engine, AuditEventPublisher audit, ParameterSanitizer sanitizer) {
        callbacks = Arrays.stream(delegate.getToolCallbacks())
            .map(callback -> new GuardedToolCallback(callback, resolver, engine, audit, sanitizer)).toArray(ToolCallback[]::new);
    }
    @Override public ToolCallback[] getToolCallbacks() { return callbacks.clone(); }
}
