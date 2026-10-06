package io.agentguard.policy.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Top-level DTO representing an uncompiled agentguard-policy.yaml document.
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record PolicyDocumentDto(
    @JsonProperty(value = "version", required = true)
    String version,

    @JsonProperty("metadata")
    Map<String, Object> metadata,

    @JsonProperty(value = "roles", required = true)
    Map<String, RoleDto> roles,

    @JsonProperty("rules")
    List<RuleDto> rules
) {
    public PolicyDocumentDto {
        metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
        roles = roles == null ? Map.of() : Map.copyOf(roles);
        rules = rules == null ? List.of() : List.copyOf(rules);
    }
}
