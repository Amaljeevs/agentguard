package io.agentguard.web.autoconfigure;

import io.agentguard.approval.ApprovalService;
import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.identity.AgentIdentityResolver;
import io.agentguard.web.api.AgentGuardAuthorizationApi;
import io.agentguard.web.api.AuthorizationApiExceptionHandler;
import io.agentguard.web.api.AuthorizationController;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;

import java.time.Duration;
import java.util.Optional;

/**
 * Spring Boot AutoConfiguration for AgentGuard Language-Neutral REST Authorization API.
 * Automatically exposes {@code POST /v1/authorize} when PolicyEngine and AgentIdentityResolver beans exist.
 */
@AutoConfiguration
@ConditionalOnWebApplication
@ConditionalOnClass(AuthorizationController.class)
@ConditionalOnBean({PolicyEngine.class, AgentIdentityResolver.class})
public class AgentGuardWebAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AgentGuardAuthorizationApi agentGuardAuthorizationApi(
            PolicyEngine policyEngine,
            AgentIdentityResolver identityResolver,
            AuditEventPublisher auditPublisher,
            ParameterSanitizer parameterSanitizer,
            Optional<ApprovalService> approvalService,
            org.springframework.beans.factory.ObjectProvider<io.agentguard.core.metrics.AgentGuardMetrics> metricsProvider) {
        return new AgentGuardAuthorizationApi(
                policyEngine,
                identityResolver,
                auditPublisher,
                parameterSanitizer,
                approvalService,
                Duration.ofMinutes(5),
                metricsProvider.getIfAvailable(() -> io.agentguard.core.metrics.AgentGuardMetrics.NOOP)
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthorizationController agentGuardAuthorizationController(AgentGuardAuthorizationApi api) {
        return new AuthorizationController(api);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthorizationApiExceptionHandler agentGuardAuthorizationApiExceptionHandler() {
        return new AuthorizationApiExceptionHandler();
    }
}

