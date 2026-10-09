package io.agentguard.spring.ai;

import io.agentguard.audit.publisher.InMemoryAuditEventPublisher;
import io.agentguard.audit.sanitizer.DefaultParameterSanitizer;
import io.agentguard.core.engine.DefaultPolicyEngine;
import io.agentguard.core.exception.*;
import io.agentguard.core.model.*;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.assertj.core.api.Assertions.*;

class GuardedToolCallbackTest {
    private final AtomicInteger calls = new AtomicInteger();
    private final InMemoryAuditEventPublisher audit = new InMemoryAuditEventPublisher();
    private final ToolCallback tool = new ToolCallback() {
        public ToolDefinition getToolDefinition() { return ToolDefinition.builder().name("refund").description("Refund order")
            .inputSchema("{\"type\":\"object\"}").build(); }
        public String call(String input) { calls.incrementAndGet(); return "done"; }
        public String call(String input, ToolContext context) {
            assertThat(context.getContext()).containsKey("trusted-agent"); return call(input);
        }
    };
    private GuardedToolCallback guarded(boolean approval) {
        var policy = PolicySet.builder("test", "1").rules(approval ? List.of(PolicyRule.builder("review", RuleEffect.APPROVAL_REQUIRED)
            .targetActions(Set.of("refund")).build()) : List.of()).build();
        return new GuardedToolCallback(tool, (name, args, context) -> AuthorizationRequest.of(
            (AgentIdentity) context.getContext().get("trusted-agent"), Action.of(name), Resource.of("order", "1"),
            AuthorizationContext.of("production")), new DefaultPolicyEngine(policy), audit, new DefaultParameterSanitizer());
    }
    private ToolContext context(String permission) {
        return new ToolContext(Map.of("trusted-agent", AgentIdentity.builder().agentId("server-agent").permission(permission).build()));
    }
    @Test void realCallbackIsExecutedWithOriginalContextAndSanitizedAudit() {
        assertThat(guarded(false).call("{\"password\":\"secret\"}", context("refund"))).isEqualTo("done");
        assertThat(calls).hasValue(1); assertThat(audit.size()).isEqualTo(2);
        assertThat(audit.getEvents().getFirst().parameters()).containsEntry("password", "[REDACTED]");
        assertThat(audit.getEvents().getLast().metadata()).containsEntry("phase", "EXECUTION_SUCCEEDED");
    }
    @Test void denyApprovalAndMissingIdentityNeverExecuteCallback() {
        assertThatThrownBy(() -> guarded(false).call("{}", context(null))).isInstanceOf(AgentAccessDeniedException.class);
        assertThatThrownBy(() -> guarded(true).call("{}", context("refund"))).isInstanceOf(AgentApprovalRequiredException.class);
        assertThatThrownBy(() -> guarded(false).call("{}", null)).isInstanceOf(AgentAccessDeniedException.class);
        assertThat(calls).hasValue(0);
    }
    @Test void malformedDuplicateAndTrailingJsonAreDenied() {
        for (String input : List.of("[]", "null", "{", "{}{}", "{\"a\":1,\"a\":2}")) {
            assertThatThrownBy(() -> guarded(false).call(input, context("refund"))).isInstanceOf(AgentAccessDeniedException.class);
        }
        assertThat(calls).hasValue(0);
    }
    @Test void modelSuppliedIdentityCannotOverrideTrustedContext() {
        assertThatThrownBy(() -> guarded(false).call("{\"roles\":[\"admin\"],\"environment\":\"development\"}", context(null)))
            .isInstanceOf(AgentAccessDeniedException.class);
        assertThat(calls).hasValue(0);
    }
}
