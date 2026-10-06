package io.agentguard.policy.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * DTO for environmental condition constraints (equals or in-list).
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record EnvironmentConditionDto(
    @JsonProperty("equals")
    String equals,

    @JsonProperty("in")
    List<String> in
) {
    public EnvironmentConditionDto {
        in = in == null ? List.of() : List.copyOf(in);
    }
}
