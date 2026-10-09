package io.agentguard.spring.boot.autoconfigure;

import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.publisher.InMemoryAuditEventPublisher;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.identity.AgentIdentityResolver;
import io.agentguard.core.model.*;
import io.agentguard.spring.annotation.AgentAuthorize;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class AutoConfigurationTest {
    public static class Tools {
        static int executed;
        @AgentAuthorize("read") public void read() { executed++; }
        @AgentAuthorize("write") public void write() { executed++; }
    }
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class, AopAutoConfiguration.class))
        .withBean(PolicySet.class, () -> PolicySet.builder("test", "1").build())
        .withBean(AgentIdentityResolver.class, () -> () -> Optional.of(AgentIdentity.builder().agentId("test").permission("read").build()))
        .withBean(Tools.class);

    @Test void customMaskWorksWithoutAdditionalKeys() {
        runner.withPropertyValues("agentguard.audit.mask-token=MASK").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(ParameterSanitizer.class).sanitize(Map.of("password", "secret"))).containsEntry("password", "MASK");
        });
    }
    @Test void disablingAuditLeavesEnforcementEnabled() {
        var publisher = new InMemoryAuditEventPublisher();
        runner.withBean(AuditEventPublisher.class, () -> publisher).withPropertyValues("agentguard.audit.enabled=false")
            .run(context -> {
                Tools.executed = 0; context.getBean(Tools.class).read();
                assertThatThrownBy(() -> context.getBean(Tools.class).write())
                    .isInstanceOf(io.agentguard.core.exception.AgentAccessDeniedException.class);
                assertThat(Tools.executed).isEqualTo(1); assertThat(publisher.size()).isZero();
            });
    }
    @Test void failureModeControlsWhetherExecutionCanStart() {
        AuditEventPublisher broken = event -> { throw new IllegalStateException("sink-secret"); };
        runner.withBean(AuditEventPublisher.class, () -> broken).run(context -> {
            Tools.executed = 0;
            assertThatThrownBy(() -> context.getBean(Tools.class).read()).hasMessage("Audit publication failed");
            assertThat(Tools.executed).isZero();
        });
        runner.withBean(AuditEventPublisher.class, () -> broken).withPropertyValues("agentguard.audit.failure-mode=BEST_EFFORT")
            .run(context -> { Tools.executed = 0; context.getBean(Tools.class).read(); assertThat(Tools.executed).isEqualTo(1); });
    }
    @Test void missingPolicyFailsStartup() {
        new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
            .withPropertyValues("agentguard.policy-location=classpath:does-not-exist.yaml")
            .run(context -> assertThat(context).hasFailed());
    }
}
