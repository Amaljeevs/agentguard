package io.agentguard.policy.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * DTO for rule conditions block.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ConditionsDto(
    @JsonProperty("environment")
    EnvironmentConditionDto environment,

    @JsonProperty("attributes")
    Map<String, Object> attributes
) {
    public ConditionsDto {
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }
}
