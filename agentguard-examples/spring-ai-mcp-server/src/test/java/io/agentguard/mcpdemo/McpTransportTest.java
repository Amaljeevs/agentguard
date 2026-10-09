package io.agentguard.mcpdemo;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.audit.publisher.InMemoryAuditEventPublisher;
import io.modelcontextprotocol.client.*;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
class McpTransportTest {
    @LocalServerPort int port;
    @Autowired JdbcTemplate jdbc;
    @Autowired InMemoryAuditEventPublisher events;
    @Autowired ObjectMapper json;

    private String auth(String user) {
        return "Basic " + Base64.getEncoder().encodeToString((user+":demo-pass").getBytes(StandardCharsets.UTF_8));
    }
    private McpSyncClient client(String user) {
        var transport = HttpClientStreamableHttpTransport.builder("http://127.0.0.1:"+port).endpoint("/mcp")
            .requestBuilder(HttpRequest.newBuilder().header("Authorization", auth(user))).build();
        var client = McpClient.sync(transport).requestTimeout(Duration.ofSeconds(15)).build();
        client.initialize();
        return client;
    }
    private HttpResponse<String> post(String user, String path, String body) throws Exception {
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path))
            .header("Authorization", auth(user)).header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test void actualMcpToolCallsEnforceTrustedIdentityAndAuditAcrossTransportThreads() {
        try (var developer = client("developer"); var operator = client("operator")) {
            assertThat(developer.listTools().tools()).extracting(McpSchema.Tool::name).contains("readOrder", "refundOrder");
            var allowed = developer.callTool(new McpSchema.CallToolRequest("readOrder", Map.of("orderId", 1, "token", "wire-secret")));
            assertThat(allowed.isError()).isFalse();
            var denied = developer.callTool(new McpSchema.CallToolRequest("readOrder", Map.of("orderId", 2, "roles", List.of("operator"), "environment", "development")));
            assertThat(denied.isError()).isTrue();
            var approval = operator.callTool(new McpSchema.CallToolRequest("refundOrder", Map.of("orderId", 2)));
            assertThat(approval.isError()).isTrue();
            assertThat(approval.content().toString()).contains("APPROVAL_REQUIRED");
            assertThat(jdbc.queryForObject("SELECT status FROM orders WHERE id=2", String.class)).isEqualTo("PAID");
            assertThat(events.getEvents()).anySatisfy(event -> {
                assertThat(event.agentId()).isEqualTo("developer");
                assertThat(event.parameters()).containsEntry("token", "[HIDDEN]");
                assertThat(event.metadata()).containsEntry("phase", "AUTHORIZATION");
            });
            assertThat(events.getEvents().toString()).doesNotContain("wire-secret");
        }
    }

    @Test void reusableApprovalApiBindsArgumentsAndExecutesOnce() throws Exception {
        jdbc.update("INSERT INTO orders VALUES (10, 'production', 'Approval plan', 'PAID')");
        var requested = post("operator", "/api/approvals/request", "{\"orderId\":10}");
        assertThat(requested.statusCode()).isEqualTo(200);
        String id = json.readTree(requested.body()).path("id").asText();
        assertThat(post("operator", "/api/approvals/"+id+"/approve", "{}").statusCode()).isEqualTo(403);
        assertThat(post("approver", "/api/approvals/"+id+"/approve", "{}").statusCode()).isEqualTo(200);
        assertThat(post("operator", "/api/approvals/"+id+"/execute", "{\"orderId\":2}").statusCode()).isEqualTo(403);
        assertThat(post("operator", "/api/approvals/"+id+"/execute", "{\"orderId\":10}").statusCode()).isEqualTo(200);
        assertThat(post("operator", "/api/approvals/"+id+"/execute", "{\"orderId\":10}").statusCode()).isEqualTo(403);
        assertThat(jdbc.queryForObject("SELECT status FROM orders WHERE id=10", String.class)).isEqualTo("REFUNDED");
    }

    @Test void unauthenticatedTransportRequestIsRejected() throws Exception {
        var response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/mcp"))
            .header("Content-Type", "application/json").header("Accept", "application/json, text/event-stream")
            .POST(HttpRequest.BodyPublishers.ofString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"))
            .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(401);
    }
}
