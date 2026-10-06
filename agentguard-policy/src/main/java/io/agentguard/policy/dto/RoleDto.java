package io.agentguard.policy.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * DTO for role definition mapping in agentguard-policy.yaml.
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record RoleDto(
    @JsonProperty("description")
    String description,

    @JsonProperty(value = "permissions", required = true)
    List<String> permissions
) {
    public RoleDto {
        permissions = permissions == null ? List.of() : List.copyOf(permissions);
    }
}
