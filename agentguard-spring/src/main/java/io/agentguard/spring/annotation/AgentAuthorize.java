package io.agentguard.spring.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation for declaring authorization requirements on methods or classes.
 * Evaluated by {@link io.agentguard.spring.aop.AgentAuthorizationAspect} prior to method execution.
 *
 * <p>Example usage:
 * <pre>{@code
 * @McpTool(name = "queryDatabase")
 * @AgentAuthorize(action = "database.query", resourceType = "database", resourceId = "#dbName")
 * public QueryResult queryDatabase(String dbName, String sql) { ... }
 * }</pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AgentAuthorize {

    /**
     * Alias for {@link #action()}.
     */
    @AliasFor("action")
    String value() default "";

    /**
     * The requested permission or action identifier (e.g. {@code "database.query"}, {@code "kubernetes.deploy"}).
     */
    @AliasFor("value")
    String action() default "";

    /**
     * The target resource type (e.g. {@code "database"}, {@code "k8s_cluster"}, {@code "file"}).
     */
    String resourceType() default "";

    /**
     * The target resource identifier. Supports Spring Expression Language (SpEL),
     * e.g. {@code "#clusterName"} or {@code "#payload.databaseId"}.
     */
    String resourceId() default "";

    /**
     * The execution environment requirement (e.g. {@code "production"}, {@code "development"}).
     * If left blank, falls back to the active AgentGuard environment configuration.
     */
    String environment() default "";
}
