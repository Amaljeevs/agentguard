package io.agentguard.orders;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.publisher.CompositeAuditEventPublisher;
import io.agentguard.audit.publisher.InMemoryAuditEventPublisher;
import io.agentguard.audit.publisher.Slf4jAuditEventPublisher;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;

@Configuration(proxyBeanMethods = false)
public class AuditConfiguration {
    @Bean
    InMemoryAuditEventPublisher recentAudit() { return new InMemoryAuditEventPublisher(); }

    @Bean
    @Primary
    AuditEventPublisher auditPublisher(JdbcTemplate jdbc, ObjectMapper mapper,
                                      InMemoryAuditEventPublisher recentAudit, ParameterSanitizer sanitizer) {
        AuditEventPublisher sqlPublisher = event -> {
            try {
                jdbc.update("INSERT INTO audit_event (event_id, event_json) VALUES (?, ?)",
                    event.eventId(), mapper.writeValueAsString(event));
            } catch (Exception exception) {
                // The library composite continues to other sinks; make a failed SQL sink visible.
                LoggerFactory.getLogger(AuditConfiguration.class).error("Could not persist audit event {}",
                    event.eventId(), exception);
                throw new IllegalStateException("Audit persistence failed", exception);
            }
        };
        return CompositeAuditEventPublisher.of(sqlPublisher, recentAudit, new Slf4jAuditEventPublisher(),
            new SanitizedAuditLogPublisher(mapper, sanitizer));
    }
}
