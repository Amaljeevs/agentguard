package io.agentguard.spring.aop;

import io.agentguard.audit.publisher.InMemoryAuditEventPublisher;
import io.agentguard.audit.sanitizer.DefaultParameterSanitizer;
import io.agentguard.core.engine.DefaultPolicyEngine;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.model.*;
import io.agentguard.spring.annotation.AgentAuthorize;
import org.junit.jupiter.api.Test;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class AuthorizationAspectTest {
    public static class Tools {
        int executions;
        @AgentAuthorize(action="orders.read", environment="#missing") public void broken(String input) { executions++; }
        @AgentAuthorize(action="orders.read", environment="#p0", resourceId="#a1") public void positional(String environment, String id) { executions++; }
        @AgentAuthorize("orders.read") public void failure() { throw new IllegalStateException("do-not-log-me"); }
    }
    private Tools proxy(Tools target, InMemoryAuditEventPublisher audit) {
        var engine = new DefaultPolicyEngine(PolicySet.builder("test", "1").build());
        var factory = new AspectJProxyFactory(target);
        factory.addAspect(new AgentAuthorizationAspect(engine,
            () -> Optional.of(AgentIdentity.builder().agentId("test").permission("orders.read").build()), audit,
            new DefaultParameterSanitizer(), "development"));
        return factory.getProxy();
    }
    @Test void unresolvedOrNullExpressionsNeverExecute() {
        var target = new Tools(); var tools = proxy(target, new InMemoryAuditEventPublisher());
        assertThatThrownBy(() -> tools.broken("production")).isInstanceOf(AgentAccessDeniedException.class);
        assertThatThrownBy(() -> tools.positional(null, "orders")).isInstanceOf(AgentAccessDeniedException.class);
        assertThat(target.executions).isZero();
    }
    @Test void positionalParametersAndLifecycleCorrelationWork() {
        var audit = new InMemoryAuditEventPublisher(); var target = new Tools();
        proxy(target, audit).positional("production", "orders");
        assertThat(target.executions).isEqualTo(1);
        assertThat(audit.getEvents()).hasSize(2);
        assertThat(audit.getEvents().get(0).metadata().get("correlationId")).isEqualTo(audit.getEvents().get(1).metadata().get("correlationId"));
        assertThat(audit.getEvents().get(1).metadata()).containsEntry("phase", "EXECUTION_SUCCEEDED");
        assertThat(audit.getEvents().get(0).environment()).isEqualTo("production");
    }
    @Test void executionFailuresAreAuditedWithoutExceptionMessages() {
        var audit = new InMemoryAuditEventPublisher();
        assertThatThrownBy(() -> proxy(new Tools(), audit).failure()).isInstanceOf(IllegalStateException.class);
        assertThat(audit.getEvents().get(1).metadata()).containsEntry("phase", "EXECUTION_FAILED");
        assertThat(audit.getEvents().toString()).doesNotContain("do-not-log-me");
    }
}
