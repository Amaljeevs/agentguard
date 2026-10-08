package io.agentguard.consumer;

import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.exception.AgentApprovalRequiredException;
import io.agentguard.mcp.error.McpAuthorizationExceptionMapper;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Supplier;

@Component
@ConditionalOnProperty(name = "demo.enabled", havingValue = "true", matchIfMissing = true)
public class DemoRunner implements CommandLineRunner {
    private final GuardedTools tools;

    public DemoRunner(GuardedTools tools) {
        this.tools = tools;
    }

    @Override
    public void run(String... args) {
        // Synthetic authentication for this local demo only. A real application must
        // establish identity/authorities through its trusted authentication provider.
        asRole("developer", () -> tools.query("orders", "development", "demo-secret"));
        asRole("developer", () -> tools.query("orders", "production", "demo-secret"));
        asRole("developer", () -> tools.deploy("orders", "development"));
        asRole("devops", () -> tools.deploy("orders", "production"));
        asRole("devops", () -> tools.deploy("orders", "development"));
        System.out.println("Executed tool bodies: " + tools.executionCount() + " (expected 2)");
    }

    private void asRole(String role, Supplier<String> operation) {
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(new UsernamePasswordAuthenticationToken(
            "demo-" + role, "N/A", List.of(new SimpleGrantedAuthority("ROLE_" + role))));
        SecurityContextHolder.setContext(context);
        try {
            System.out.println("ALLOW: " + operation.get());
        } catch (AgentAccessDeniedException | AgentApprovalRequiredException exception) {
            var error = McpAuthorizationExceptionMapper.toMcpError(exception);
            System.out.printf("BLOCKED: code=%d data=%s%n", error.code(), error.data());
        } finally {
            SecurityContextHolder.clearContext();
        }
    }
}
