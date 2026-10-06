package io.agentguard.spring.boot.autoconfigure;

import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.publisher.Slf4jAuditEventPublisher;
import io.agentguard.audit.sanitizer.DefaultParameterSanitizer;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.DefaultPermissionMatcher;
import io.agentguard.core.engine.DefaultPolicyEngine;
import io.agentguard.core.engine.PermissionMatcher;
import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.exception.InvalidPolicyException;
import io.agentguard.core.identity.AgentIdentityResolver;
import io.agentguard.core.model.PolicySet;
import io.agentguard.policy.loader.PolicyLoader;
import io.agentguard.policy.loader.YamlPolicyLoader;
import io.agentguard.spring.aop.AgentAuthorizationAspect;
import io.agentguard.spring.security.SpringSecurityAgentIdentityResolver;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;

/**
 * Spring Boot AutoConfiguration for AgentGuard.
 */
@AutoConfiguration
@EnableConfigurationProperties(AgentGuardProperties.class)
@ConditionalOnProperty(prefix = "agentguard", name = "enabled", havingValue = "true", matchIfMissing = true)
public class AgentGuardAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PolicyLoader agentGuardPolicyLoader() {
        return new YamlPolicyLoader();
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionMatcher agentGuardPermissionMatcher() {
        return new DefaultPermissionMatcher();
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicySet agentGuardPolicySet(
        AgentGuardProperties properties,
        PolicyLoader policyLoader,
        ResourceLoader resourceLoader
    ) {
        String location = properties.getPolicyLocation();
        Resource resource = resourceLoader.getResource(location);

        if (!resource.exists()) {
            throw new InvalidPolicyException(
                "AgentGuard policy file not found at configured location: " + location
            );
        }

        try (InputStream is = resource.getInputStream()) {
            return policyLoader.load(is);
        } catch (IOException e) {
            throw new InvalidPolicyException("Failed to read AgentGuard policy at " + location, e);
        }
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyEngine agentGuardPolicyEngine(PolicySet policySet, PermissionMatcher permissionMatcher) {
        return new DefaultPolicyEngine(policySet, permissionMatcher);
    }

    @Bean
    @ConditionalOnMissingBean
    public ParameterSanitizer agentGuardParameterSanitizer(AgentGuardProperties properties) {
        if (!properties.getAudit().getSensitiveKeys().isEmpty()) {
            Set<String> keys = new HashSet<>(DefaultParameterSanitizer.DEFAULT_SENSITIVE_KEYS);
            keys.addAll(properties.getAudit().getSensitiveKeys());
            return new DefaultParameterSanitizer(keys, properties.getAudit().getMaskToken());
        }
        return new DefaultParameterSanitizer();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuditEventPublisher agentGuardAuditEventPublisher() {
        return new Slf4jAuditEventPublisher();
    }

    @Bean
    @ConditionalOnMissingBean
    public AgentIdentityResolver agentGuardIdentityResolver() {
        return new SpringSecurityAgentIdentityResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public AgentAuthorizationAspect agentAuthorizationAspect(
        PolicyEngine policyEngine,
        AgentIdentityResolver identityResolver,
        AuditEventPublisher auditPublisher,
        ParameterSanitizer parameterSanitizer,
        AgentGuardProperties properties
    ) {
        return new AgentAuthorizationAspect(
            policyEngine,
            identityResolver,
            auditPublisher,
            parameterSanitizer,
            properties.getEnvironment()
        );
    }
}
