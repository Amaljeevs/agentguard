package io.agentguard.policy.testing;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.core.engine.DefaultPolicyEngine;
import io.agentguard.core.model.*;
import io.agentguard.policy.loader.YamlPolicyLoader;
import java.io.*;
import java.util.*;

/** Run declarative policy expectations in CI without starting Spring. */
public final class PolicyTestCli {
    private PolicyTestCli() {}
    public record Scenario(String name, String agentId, Set<String> roles, Set<String> permissions,
                           String action, String resourceType, String resourceId, String environment, Decision expected) {}
    public static void main(String[] args) { System.exit(run(args, System.out)); }

    public static int run(String[] args, PrintStream output) {
        if (args.length != 2) { output.println("Usage: PolicyTestCli <policy.yaml> <scenarios.json>"); return 2; }
        try {
            var engine = new DefaultPolicyEngine(new YamlPolicyLoader().load(new File(args[0])));
            List<Scenario> cases = new ObjectMapper().readValue(new File(args[1]), new TypeReference<>() {});
            if (cases.isEmpty()) throw new IllegalArgumentException("No scenarios");
            int failures = 0;
            output.println("Policy revision: " + engine.revision());
            for (Scenario scenario : cases) {
                Objects.requireNonNull(scenario.expected(), "Expected decision is required");
                var request = AuthorizationRequest.of(AgentIdentity.builder().agentId(scenario.agentId())
                    .roles(scenario.roles()).permissions(scenario.permissions()).build(), Action.of(scenario.action()),
                    Resource.of(scenario.resourceType(), scenario.resourceId()), AuthorizationContext.of(scenario.environment()));
                var result = engine.evaluate(request);
                boolean passed = result.decision() == scenario.expected();
                if (!passed) failures++;
                output.printf("%s %s: %s; rule=%s; %s%n", passed ? "PASS" : "FAIL", scenario.name(), result.decision(),
                    result.matchedRuleId().orElse("none"), result.reason());
            }
            return failures == 0 ? 0 : 1;
        } catch (Exception failure) { output.println("Invalid policy test input: " + failure.getClass().getSimpleName()); return 2; }
    }
}
