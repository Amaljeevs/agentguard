package io.agentguard.spring.ai;

import io.agentguard.core.model.AuthorizationRequest;
import org.springframework.ai.chat.model.ToolContext;
import java.util.Map;

/** Resolve identity from authenticated server context and environment/resource from trusted metadata. */
@FunctionalInterface
public interface ToolAuthorizationResolver {
    AuthorizationRequest resolve(String toolName, Map<String, Object> arguments, ToolContext context);
}
