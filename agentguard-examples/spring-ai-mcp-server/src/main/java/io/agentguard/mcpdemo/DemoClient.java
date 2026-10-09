package io.agentguard.mcpdemo;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.*;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

/** A real MCP client walkthrough; no model API key required. Run against a freshly started server. */
public final class DemoClient {
    private static String base;
    public static void main(String[] args) throws Exception {
        base = args.length == 0 ? "http://localhost:8082" : args[0];
        try (var developer = client("developer"); var operator = client("operator")) {
            System.out.println("TOOLS: " + developer.listTools().tools().stream().map(McpSchema.Tool::name).toList());
            System.out.println("ALLOW: " + developer.callTool(new McpSchema.CallToolRequest("readOrder", Map.of("orderId", 1, "token", "demo-secret"))));
            System.out.println("DENY: " + developer.callTool(new McpSchema.CallToolRequest("readOrder", Map.of("orderId", 2))));
            System.out.println("APPROVAL REQUIRED: " + operator.callTool(new McpSchema.CallToolRequest("refundOrder", Map.of("orderId", 2))));
            String ticket = post("operator", "/api/approvals/request", "{\"orderId\":2}");
            String id = new ObjectMapper().readTree(ticket).path("id").asText();
            post("approver", "/api/approvals/"+id+"/approve", "{}");
            System.out.println("APPROVED EXECUTION: " + post("operator", "/api/approvals/"+id+"/execute", "{\"orderId\":2}"));
            developer.closeGracefully();
            operator.closeGracefully();
        } finally {
            // This standalone client owns its Reactor scheduler lifecycle.
            reactor.core.scheduler.Schedulers.shutdownNow();
        }
    }
    private static String auth(String user) { return "Basic " + Base64.getEncoder().encodeToString((user+":demo-pass").getBytes(StandardCharsets.UTF_8)); }
    private static McpSyncClient client(String user) {
        var transport = HttpClientStreamableHttpTransport.builder(base).endpoint("/mcp")
            .requestBuilder(HttpRequest.newBuilder().header("Authorization", auth(user))).build();
        var client = McpClient.sync(transport).requestTimeout(Duration.ofSeconds(15)).build();
        client.initialize(); return client;
    }
    private static String post(String user, String path, String body) throws Exception {
        try (var http = HttpClient.newHttpClient()) {
        var response = http.send(HttpRequest.newBuilder(URI.create(base+path))
            .header("Authorization", auth(user)).header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) throw new IllegalStateException("Demo request failed: HTTP " + response.statusCode());
        return response.body();
        }
    }
}
