package io.agentguard.policy.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * DTO for rule conditions block supporting arguments, subject attributes,
 * resource tags, environment, tenant, and context conditions.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ConditionsDto(
    @JsonProperty("environment")
    Object environment,

    @JsonProperty("arguments")
    Map<String, Object> arguments,

    @JsonProperty("subject")
    Map<String, Object> subject,

    @JsonProperty("resource")
    Map<String, Object> resource,

    @JsonProperty("tenant")
    Object tenant,

    @JsonProperty("context")
    Map<String, Object> context,

    @JsonProperty("attributes")
    Map<String, Object> attributes
) {
    public ConditionsDto {
        arguments = arguments == null ? Map.of() : Map.copyOf(arguments);
        subject = subject == null ? Map.of() : Map.copyOf(subject);
        resource = resource == null ? Map.of() : Map.copyOf(resource);
        context = context == null ? Map.of() : Map.copyOf(context);
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }
}
