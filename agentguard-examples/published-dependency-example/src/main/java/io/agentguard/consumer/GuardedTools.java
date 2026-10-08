package io.agentguard.consumer;

import io.agentguard.spring.annotation.AgentAuthorize;
import org.springframework.stereotype.Service;

import java.util.concurrent.atomic.AtomicInteger;

@Service
public class GuardedTools {
    private final AtomicInteger executions = new AtomicInteger();

    @AgentAuthorize(action = "database.query", resourceType = "database",
        resourceId = "#database", environment = "#environment")
    public String query(String database, String environment, String password) {
        executions.incrementAndGet();
        return "Simulated query on " + database + " in " + environment;
    }

    @AgentAuthorize(action = "kubernetes.deploy", resourceType = "service",
        resourceId = "#service", environment = "#environment")
    public String deploy(String service, String environment) {
        executions.incrementAndGet();
        return "Simulated deployment of " + service + " in " + environment;
    }

    public int executionCount() {
        return executions.get();
    }
}
