package io.agentguard.spring.ai;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.audit.execution.AuthorizationExecutor;
import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.model.*;
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.ai.tool.metadata.ToolMetadata;
import java.util.Map;
import java.util.Objects;

/** Wrap every callback exposed to the model/server. No proxy or annotation self-invocation dependency. */
public final class GuardedToolCallback implements ToolCallback {
    private static final ObjectMapper JSON = new ObjectMapper()
        .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final ToolCallback delegate;
    private final ToolAuthorizationResolver resolver;
    private final AuthorizationExecutor executor;

    public GuardedToolCallback(ToolCallback delegate, ToolAuthorizationResolver resolver, PolicyEngine engine,
                               AuditEventPublisher audit, ParameterSanitizer sanitizer) {
        this.delegate = Objects.requireNonNull(delegate); this.resolver = Objects.requireNonNull(resolver);
        this.executor = new AuthorizationExecutor(engine, audit, sanitizer);
    }
    @Override public ToolDefinition getToolDefinition() { return delegate.getToolDefinition(); }
    @Override public ToolMetadata getToolMetadata() { return delegate.getToolMetadata(); }
    @Override public String call(String input) { return call(input, null); }

    @Override public String call(String input, ToolContext context) {
        Map<String, Object> arguments;
        try {
            if (input == null || input.length() > 1_048_576) throw new IllegalArgumentException();
            arguments = JSON.readValue(input, new TypeReference<Map<String, Object>>() {});
            if (arguments == null) throw new IllegalArgumentException();
        } catch (Exception invalid) { throw new AgentAccessDeniedException("Tool arguments must be a valid JSON object"); }
        AuthorizationRequest resolved;
        try { resolved = Objects.requireNonNull(resolver.resolve(getToolDefinition().name(), arguments, context)); }
        catch (AgentAccessDeniedException denied) { throw denied; }
        catch (RuntimeException failure) { throw new AgentAccessDeniedException("Could not resolve trusted tool authorization context"); }
        // Always audit the arguments that actually reach the callback, not a resolver's substitute parameters.
        var request = AuthorizationRequest.of(resolved.subject(), Action.of(resolved.action().name(), arguments),
            resolved.resource(), AuthorizationContext.of(resolved.context().environment(), resolved.context().metadata()));
        try { return executor.execute(request, () -> delegate.call(input, context)); }
        catch (RuntimeException | Error failure) { throw failure; }
        catch (Throwable failure) { throw new IllegalStateException("Tool execution failed"); }
    }
}
