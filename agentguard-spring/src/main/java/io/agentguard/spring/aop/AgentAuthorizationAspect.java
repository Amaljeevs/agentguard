package io.agentguard.spring.aop;

import io.agentguard.audit.model.AuditEvent;
import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.sanitizer.DefaultParameterSanitizer;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.exception.AgentApprovalRequiredException;
import io.agentguard.core.identity.AgentIdentityResolver;
import io.agentguard.core.model.Action;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.AuthorizationContext;
import io.agentguard.core.model.AuthorizationDecision;
import io.agentguard.core.model.AuthorizationRequest;
import io.agentguard.core.model.Resource;
import io.agentguard.spring.annotation.AgentAuthorize;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Spring AOP Aspect intercepting methods annotated with {@link AgentAuthorize}.
 * Translates method invocations into {@link AuthorizationRequest} domain objects,
 * invokes {@link PolicyEngine}, publishes audit records, and enforces access decisions.
 */
@Aspect
public class AgentAuthorizationAspect {

    private final PolicyEngine policyEngine;
    private final AgentIdentityResolver identityResolver;
    private final AuditEventPublisher auditPublisher;
    private final ParameterSanitizer parameterSanitizer;
    private final String defaultEnvironment;

    private final ExpressionParser spelParser = new SpelExpressionParser();
    private final ParameterNameDiscoverer paramNameDiscoverer = new DefaultParameterNameDiscoverer();

    public AgentAuthorizationAspect(
        PolicyEngine policyEngine,
        AgentIdentityResolver identityResolver,
        AuditEventPublisher auditPublisher,
        ParameterSanitizer parameterSanitizer,
        String defaultEnvironment
    ) {
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine must not be null");
        this.identityResolver = Objects.requireNonNull(identityResolver, "identityResolver must not be null");
        this.auditPublisher = Objects.requireNonNull(auditPublisher, "auditPublisher must not be null");
        this.parameterSanitizer = parameterSanitizer != null ? parameterSanitizer : new DefaultParameterSanitizer();
        this.defaultEnvironment = (defaultEnvironment != null && !defaultEnvironment.isBlank())
            ? defaultEnvironment : "development";
    }

    @Around("@annotation(agentAuthorize)")
    public Object authorizeMethod(ProceedingJoinPoint joinPoint, AgentAuthorize agentAuthorize) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        Object[] args = joinPoint.getArgs();

        // 1. Resolve active AgentIdentity
        Optional<AgentIdentity> identityOpt = identityResolver.resolveCurrentIdentity();
        if (identityOpt.isEmpty()) {
            throw new AgentAccessDeniedException("AgentGuard authorization DENIED: No authenticated agent identity found in context");
        }
        AgentIdentity subject = identityOpt.get();

        // 2. Extract action name
        String actionName = !agentAuthorize.action().isBlank()
            ? agentAuthorize.action()
            : agentAuthorize.value();
        if (actionName.isBlank()) {
            actionName = method.getDeclaringClass().getSimpleName() + "." + method.getName();
        }

        // 3. Extract parameter names and values
        Map<String, Object> parameters = extractParameters(method, args);

        // 4. Resolve SpEL for resourceId & environment
        EvaluationContext evalContext = createEvaluationContext(method, args);
        String resourceId = resolveSpel(agentAuthorize.resourceId(), evalContext, "default-resource");
        String resourceType = !agentAuthorize.resourceType().isBlank() ? agentAuthorize.resourceType() : "tool";
        String environment = resolveSpel(agentAuthorize.environment(), evalContext, defaultEnvironment);

        // 5. Construct domain request
        AuthorizationRequest request = AuthorizationRequest.of(
            subject,
            Action.of(actionName, parameters),
            Resource.of(resourceType, resourceId),
            AuthorizationContext.of(environment)
        );

        // 6. Evaluate decision via pure PDP
        AuthorizationDecision decision = policyEngine.evaluate(request);

        // 7. Publish audit record
        AuditEvent auditEvent = AuditEvent.from(request, decision, parameterSanitizer);
        auditPublisher.publish(auditEvent);

        // 8. Enforce decision outcome
        if (decision.isDenied()) {
            String ruleSuffix = decision.matchedRuleId().map(r -> " [rule: " + r + "]").orElse("");
            throw new AgentAccessDeniedException(
                String.format("AgentGuard authorization DENIED: %s%s", decision.reason(), ruleSuffix),
                decision
            );
        }

        if (decision.isApprovalRequired()) {
            String ruleSuffix = decision.matchedRuleId().map(r -> " [rule: " + r + "]").orElse("");
            throw new AgentApprovalRequiredException(
                String.format("AgentGuard APPROVAL_REQUIRED: %s%s", decision.reason(), ruleSuffix),
                decision
            );
        }

        // 9. ALLOW: proceed with method execution
        return joinPoint.proceed();
    }

    private Map<String, Object> extractParameters(Method method, Object[] args) {
        Map<String, Object> params = new HashMap<>();
        String[] paramNames = paramNameDiscoverer.getParameterNames(method);
        if (paramNames != null && args != null) {
            for (int i = 0; i < Math.min(paramNames.length, args.length); i++) {
                params.put(paramNames[i], args[i]);
            }
        }
        return params;
    }

    private EvaluationContext createEvaluationContext(Method method, Object[] args) {
        StandardEvaluationContext context = new StandardEvaluationContext();
        String[] paramNames = paramNameDiscoverer.getParameterNames(method);
        if (paramNames != null && args != null) {
            for (int i = 0; i < Math.min(paramNames.length, args.length); i++) {
                context.setVariable(paramNames[i], args[i]);
            }
        }
        return context;
    }

    private String resolveSpel(String expressionStr, EvaluationContext context, String fallback) {
        if (expressionStr == null || expressionStr.isBlank()) {
            return fallback;
        }
        if (expressionStr.startsWith("#")) {
            try {
                Object value = spelParser.parseExpression(expressionStr).getValue(context);
                return value != null ? value.toString() : fallback;
            } catch (Exception e) {
                return fallback;
            }
        }
        return expressionStr;
    }
}
