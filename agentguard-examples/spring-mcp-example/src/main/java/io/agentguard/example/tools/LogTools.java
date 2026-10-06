package io.agentguard.example.tools;

import io.agentguard.spring.annotation.AgentAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Example log extraction tools.
 */
@Service
public class LogTools {

    @AgentAuthorize("logs.read")
    public List<String> fetchRecentLogs(String serviceName, int lineCount) {
        return List.of(
            "[INFO] Service " + serviceName + " initialized",
            "[INFO] Health check OK"
        );
    }
}
