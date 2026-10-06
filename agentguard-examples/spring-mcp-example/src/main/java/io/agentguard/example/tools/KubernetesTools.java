package io.agentguard.example.tools;

import io.agentguard.spring.annotation.AgentAuthorize;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Example Kubernetes infrastructure tools.
 */
@Service
public class KubernetesTools {

    /**
     * Service deployment tool.
     * Evaluates permission "kubernetes.deploy".
     * In development: ALLOW for devops agents.
     * In production: APPROVAL_REQUIRED due to rule 'prod-deploy-approval'.
     */
    @AgentAuthorize(
        action = "kubernetes.deploy",
        resourceType = "k8s_cluster",
        resourceId = "#clusterId",
        environment = "#environment"
    )
    public Map<String, Object> deployService(String clusterId, String serviceName, String imageTag, String environment) {
        return Map.of(
            "cluster", clusterId,
            "service", serviceName,
            "status", "DEPLOYED",
            "image", imageTag
        );
    }
}
