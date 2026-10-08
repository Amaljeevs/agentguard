package io.agentguard.orders;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.audit.model.AuditEvent;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.model.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuditLogTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired ParameterSanitizer sanitizer;
    private final Logger logger = (Logger) LoggerFactory.getLogger("io.agentguard.orders.audit.json");
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void captureLogs() {
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void stopCapture() {
        logger.detachAppender(appender);
        appender.stop();
    }

    @Test
    void allowedAndDeniedRequestsLogOnlySanitizedParameters() throws Exception {
        String payload = """
            {"product":"Log demo", "amount":12, "customerEmail":"log-private@example.test",
             "password":"log-password-secret", "internalNote":"log-private-note",
             "integration":{"API-Key":"log-nested-secret","region":"local"},
             "attempts":[{"ToKeN":"log-list-secret","result":"ok"}]}
            """;
        mvc.perform(post("/api/databases/orders-dev/orders").with(user("developer").roles("DEVELOPER"))
                .with(csrf()).contentType("application/json").content(payload))
            .andExpect(status().isCreated());
        mvc.perform(post("/api/databases/orders-prod/orders").with(user("developer").roles("DEVELOPER"))
                .with(csrf()).contentType("application/json").content(payload))
            .andExpect(status().isForbidden());

        assertThat(appender.list).hasSize(2);
        assertThat(appender.list.get(0).getLevel()).isEqualTo(Level.INFO);
        assertThat(appender.list.get(1).getLevel()).isEqualTo(Level.WARN);
        for (var event : appender.list) {
            String message = event.getFormattedMessage();
            assertThat(message).doesNotContain("log-private@example.test", "log-password-secret", "log-private-note",
                "log-nested-secret", "log-list-secret", "\n", "\r");
            var json = mapper.readTree(message);
            assertThat(json.path("action").asText()).isEqualTo("orders.create");
            var parameters = json.path("parameters").path("payload");
            for (String key : List.of("customerEmail", "password", "internalNote")) {
                assertThat(parameters.path(key).asText()).isEqualTo("[HIDDEN]");
            }
            assertThat(parameters.path("integration").path("API-Key").asText()).isEqualTo("[HIDDEN]");
            assertThat(parameters.path("attempts").get(0).path("ToKeN").asText()).isEqualTo("[HIDDEN]");
            assertThat(parameters.path("integration").path("region").asText()).isEqualTo("local");
        }
    }

    @Test
    void manuallyPublishedParametersAreSanitizedAndNewlinesAreEscaped() throws Exception {
        var request = AuthorizationRequest.of(AgentIdentity.builder().agentId("log-demo").build(),
            Action.of("orders.read", Map.of("password", "manual-secret", "product", "line1\nline2")),
            Resource.of("database", "orders-dev"), AuthorizationContext.of("development"));
        // Deliberately bypass sanitization at construction to exercise the logging boundary.
        var event = AuditEvent.from(request, AuthorizationDecision.allow("demo", "demo"), parameters -> parameters);
        new SanitizedAuditLogPublisher(mapper, sanitizer).publish(event);
        String message = appender.list.getFirst().getFormattedMessage();
        assertThat(message).doesNotContain("manual-secret", "\n", "\r");
        var parameters = mapper.readTree(message).path("parameters");
        assertThat(parameters.path("password").asText()).isEqualTo("[HIDDEN]");
        assertThat(parameters.path("product").asText()).isEqualTo("line1\nline2");
    }

    @Test
    void serializationFailureDoesNotLogRawInputOrExceptionMessage() {
        Object unserializable = new Object() {
            public String getValue() { throw new IllegalStateException("failure-path-secret"); }
        };
        var request = AuthorizationRequest.of(AgentIdentity.builder().agentId("log-demo").build(),
            Action.of("orders.read", Map.of("input", unserializable)),
            Resource.of("database", "orders-dev"), AuthorizationContext.of("development"));
        var event = AuditEvent.from(request, AuthorizationDecision.allow("demo", "demo"), sanitizer);
        new SanitizedAuditLogPublisher(mapper, sanitizer).publish(event);
        assertThat(appender.list).singleElement().satisfies(log -> {
            assertThat(log.getLevel()).isEqualTo(Level.ERROR);
            assertThat(log.getFormattedMessage()).isEqualTo("Could not serialize sanitized audit event");
            assertThat(log.getThrowableProxy()).isNull();
        });
    }
}
