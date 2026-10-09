package io.agentguard.audit.publisher;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.audit.model.AuditEvent;
import io.agentguard.audit.sanitizer.DefaultParameterSanitizer;
import io.agentguard.core.model.*;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class JsonAuditEventPublisherTest {
    @Test void logsRedactedDtoAndMetadataWithOneLinePerRecord() throws Exception {
        record Payload(String password, String name) {}
        var logger = (Logger) LoggerFactory.getLogger("test.audit.json");
        var appender = new ListAppender<ILoggingEvent>(); appender.start(); logger.addAppender(appender);
        try {
            var parameters = new HashMap<String,Object>();
            parameters.put("payload", new Payload("dto-secret", "line1\nline2")); parameters.put("nullable", null);
            var request = AuthorizationRequest.of(AgentIdentity.builder().agentId("agent").build(), Action.of("read", parameters),
                Resource.of("database", "1"), AuthorizationContext.of("dev", Map.of("token", "metadata-secret")));
            var event = AuditEvent.from(request, AuthorizationDecision.allow("demo", "test"), map -> map)
                .lifecycle("AUTHORIZATION", "correlation", "revision", Map.of());
            new JsonAuditEventPublisher(new DefaultParameterSanitizer(), logger).publish(event);
            String message = appender.list.getFirst().getFormattedMessage();
            assertThat(message).doesNotContain("dto-secret", "metadata-secret", "\n", "\r");
            var json = new ObjectMapper().readTree(message);
            assertThat(json.path("parameters").path("payload").path("password").asText()).isEqualTo("[REDACTED]");
            assertThat(json.path("parameters").path("payload").path("name").asText()).isEqualTo("line1\nline2");
            assertThat(json.path("parameters").path("nullable").isNull()).isTrue();
            assertThat(json.path("metadata").path("token").asText()).isEqualTo("[REDACTED]");
        } finally { logger.detachAppender(appender); appender.stop(); }
    }
    @Test void strictCompositeAttemptsAllSinksThenFailsWithoutExposingOriginalException() {
        var capture = new InMemoryAuditEventPublisher();
        AuditEventPublisher broken = event -> { throw new IllegalStateException("sensitive-message"); };
        var composite = new CompositeAuditEventPublisher(List.of(broken, capture), AuditFailureMode.FAIL_CLOSED);
        var request = AuthorizationRequest.of(AgentIdentity.builder().agentId("test").build(), Action.of("read"),
            Resource.of("test", "1"), AuthorizationContext.of("dev"));
        var event = AuditEvent.from(request, AuthorizationDecision.allow("demo", "test"), new DefaultParameterSanitizer());
        assertThatThrownBy(() -> composite.publish(event)).isInstanceOf(IllegalStateException.class)
            .hasMessage("One or more audit publishers failed").hasNoCause();
        assertThat(capture.getEvents()).containsExactly(event);
    }
}
