package io.agentguard.policy.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * DTO for target matching in policy rules.
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record TargetDto(
    @JsonProperty("roles")
    List<String> roles,

    @JsonProperty("actions")
    List<String> actions,

    @JsonProperty("resources")
    ResourceTargetDto resources,

    @JsonProperty("conditions")
    ConditionsDto conditions
) {
    public TargetDto {
        roles = roles == null ? List.of() : List.copyOf(roles);
        actions = actions == null ? List.of() : List.copyOf(actions);
    }
}
