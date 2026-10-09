package io.agentguard.mcpdemo;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.audit.publisher.*;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.spring.ai.GuardedToolCallback;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.*;
import io.modelcontextprotocol.server.transport.WebMvcStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import org.springframework.ai.mcp.McpToolUtils;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.context.annotation.*;
import org.springframework.web.servlet.function.*;
import java.util.*;

@Configuration(proxyBeanMethods = false)
public class McpConfiguration {
    @Bean WebMvcStreamableServerTransportProvider transport(TrustedAgents agents) {
        return WebMvcStreamableServerTransportProvider.builder().mcpEndpoint("/mcp")
            .contextExtractor(request -> McpTransportContext.create(Map.of("agentguard.identity",
                agents.resolve(request.principal().orElse(null))))).build();
    }
    @Bean RouterFunction<ServerResponse> mcpRoutes(WebMvcStreamableServerTransportProvider transport) {
        return transport.getRouterFunction();
    }
    @Bean InMemoryAuditEventPublisher events() { return new InMemoryAuditEventPublisher(); }
    @Bean @Primary AuditEventPublisher auditPublisher(InMemoryAuditEventPublisher events, ParameterSanitizer sanitizer) {
        return new CompositeAuditEventPublisher(List.of(events, new JsonAuditEventPublisher(sanitizer)), AuditFailureMode.FAIL_CLOSED);
    }
    @Bean(destroyMethod="close") McpSyncServer mcpServer(WebMvcStreamableServerTransportProvider transport,
            OrderTools orders, PolicyEngine engine, AuditEventPublisher audit, ParameterSanitizer sanitizer, ObjectMapper json) {
        List<ToolCallback> callbacks = new ArrayList<>();
        for (String name : List.of("readOrder", "refundOrder")) {
            ToolCallback operation = new ToolCallback() {
                public ToolDefinition getToolDefinition() { return ToolDefinition.builder().name(name).description(name + " from the demo order database")
                    .inputSchema("{\"type\":\"object\",\"properties\":{\"orderId\":{\"type\":\"integer\"},\"token\":{\"type\":\"string\"}},\"required\":[\"orderId\"]}").build(); }
                public String call(String input) {
                    try { return orders.execute(name, json.readValue(input, new TypeReference<Map<String, Object>>() {})); }
                    catch (com.fasterxml.jackson.core.JsonProcessingException failure) { throw new IllegalArgumentException("Invalid tool arguments"); }
                }
            };
            callbacks.add(new GuardedToolCallback(operation, (tool, arguments, context) -> {
                var exchange = McpToolUtils.getMcpExchange(context).orElseThrow();
                var identity = (AgentIdentity) exchange.transportContext().get("agentguard.identity");
                return orders.request(tool, arguments, identity);
            }, engine, audit, sanitizer));
        }
        return McpServer.sync(transport).serverInfo("agentguard-orders", "0.2.0")
            .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
            .tools(McpToolUtils.toSyncToolSpecifications(callbacks.toArray(ToolCallback[]::new))).build();
    }
}
