package io.agentguard.benchmarks;

import io.agentguard.core.engine.DefaultPolicyEngine;
import io.agentguard.core.model.*;
import io.agentguard.audit.sanitizer.DefaultParameterSanitizer;
import org.openjdk.jmh.annotations.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations=3)
@Measurement(iterations=5)
@Fork(2)
public class PolicyBenchmark {
    @Param({"10", "100", "1000"}) public int ruleCount;
    private DefaultPolicyEngine engine;
    private AuthorizationRequest request;
    private final DefaultParameterSanitizer sanitizer = new DefaultParameterSanitizer();
    private final Map<String, Object> parameters = Map.of("payload", Map.of("password", "demo-secret", "product", "plan"));
    @Setup public void setup() {
        var rules = new ArrayList<PolicyRule>();
        for (int i=0; i<ruleCount; i++) rules.add(PolicyRule.builder("deny-"+i, RuleEffect.DENY).targetActions(Set.of("unrelated."+i)).build());
        engine = new DefaultPolicyEngine(PolicySet.builder("benchmark", "1").rules(rules).build());
        var identity = AgentIdentity.builder().agentId("benchmark-agent").permission("orders.*").expiresAt(Instant.now().plusSeconds(86400)).build();
        request = AuthorizationRequest.of(identity, Action.of("orders.read", parameters), Resource.of("order", "1"), AuthorizationContext.of("development"));
    }
    @Benchmark public AuthorizationDecision evaluate() { return engine.evaluate(request); }
    @Benchmark public Map<String,Object> sanitize() { return sanitizer.sanitize(parameters); }
}