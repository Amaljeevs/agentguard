package io.agentguard.policy.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * DTO representing an individual rule item in the rules array.
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record RuleDto(
    @JsonProperty(value = "id", required = true)
    String id,

    @JsonProperty("description")
    String description,

    @JsonProperty(value = "effect", required = true)
    String effect,

    @JsonProperty("target")
    TargetDto target
) {}
