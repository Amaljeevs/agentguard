package io.agentguard.policy.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * DTO for resource targeting in policy rules.
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record ResourceTargetDto(
    @JsonProperty("type")
    String type,

    @JsonProperty("id")
    String id
) {}
