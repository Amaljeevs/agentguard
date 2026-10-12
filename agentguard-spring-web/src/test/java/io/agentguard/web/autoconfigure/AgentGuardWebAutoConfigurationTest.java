package io.agentguard.web.autoconfigure;

import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.sanitizer.DefaultParameterSanitizer;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.DefaultPolicyEngine;
import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.identity.AgentIdentityResolver;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.PolicySet;
import io.agentguard.web.api.AgentGuardAuthorizationApi;
import io.agentguard.web.api.AuthorizationApiExceptionHandler;
import io.agentguard.web.api.AuthorizationController;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class AgentGuardWebAutoConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AgentGuardWebAutoConfiguration.class))
            .withBean(PolicyEngine.class, () -> new DefaultPolicyEngine(PolicySet.builder("test", "1.0").build()))
            .withBean(AgentIdentityResolver.class, () -> () -> Optional.of(AgentIdentity.builder().agentId("test-agent").build()))
            .withBean(AuditEventPublisher.class, () -> event -> {})
            .withBean(ParameterSanitizer.class, DefaultParameterSanitizer::new);

    @Test
    void shouldAutoConfigureWebBeansWhenEngineAndIdentityResolverPresent() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(AgentGuardAuthorizationApi.class);
            assertThat(context).hasSingleBean(AuthorizationController.class);
            assertThat(context).hasSingleBean(AuthorizationApiExceptionHandler.class);
        });
    }

    @Test
    void shouldBackOffWhenPolicyEngineMissing() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(AgentGuardWebAutoConfiguration.class))
                .withBean(AgentIdentityResolver.class, () -> () -> Optional.of(AgentIdentity.builder().agentId("test-agent").build()))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(AuthorizationController.class);
                    assertThat(context).doesNotHaveBean(AgentGuardAuthorizationApi.class);
                });
    }
}

