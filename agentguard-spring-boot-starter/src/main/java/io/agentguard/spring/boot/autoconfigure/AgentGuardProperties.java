package io.agentguard.spring.boot.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for AgentGuard.
 */
@ConfigurationProperties(prefix = "agentguard")
public class AgentGuardProperties {

    /**
     * Whether AgentGuard authorization and governance is enabled.
     */
    private boolean enabled = true;

    /**
     * Location of the declarative policy file (YAML).
     */
    private String policyLocation = "classpath:agentguard-policy.yaml";

    /**
     * Default execution environment context if not specified by the tool.
     */
    private String environment = "development";

    /**
     * Audit configuration settings.
     */
    private AuditProperties audit = new AuditProperties();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getPolicyLocation() {
        return policyLocation;
    }

    public void setPolicyLocation(String policyLocation) {
        this.policyLocation = policyLocation;
    }

    public String getEnvironment() {
        return environment;
    }

    public void setEnvironment(String environment) {
        this.environment = environment;
    }

    public AuditProperties getAudit() {
        return audit;
    }

    public void setAudit(AuditProperties audit) {
        this.audit = audit;
    }

    public static class AuditProperties {
        private boolean enabled = true;
        private String maskToken = "[REDACTED]";
        private List<String> sensitiveKeys = new ArrayList<>();

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getMaskToken() {
            return maskToken;
        }

        public void setMaskToken(String maskToken) {
            this.maskToken = maskToken;
        }

        public List<String> getSensitiveKeys() {
            return sensitiveKeys;
        }

        public void setSensitiveKeys(List<String> sensitiveKeys) {
            this.sensitiveKeys = sensitiveKeys;
        }
    }
}
