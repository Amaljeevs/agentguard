package io.agentguard.policy.loader;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.agentguard.core.exception.InvalidPolicyException;
import io.agentguard.core.model.PolicyRule;
import io.agentguard.core.model.PolicySet;
import io.agentguard.core.model.RoleDefinition;
import io.agentguard.core.model.RuleEffect;
import io.agentguard.policy.dto.PolicyDocumentDto;
import io.agentguard.policy.dto.RoleDto;
import io.agentguard.policy.dto.RuleDto;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Production implementation of {@link PolicyLoader} parsing and compiling YAML policy files.
 * Enforces fail-closed schema validation and constructs immutable core {@link PolicySet} instances.
 */
public class YamlPolicyLoader implements PolicyLoader {

    private final ObjectMapper yamlMapper;

    public YamlPolicyLoader() {
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
    }

    public YamlPolicyLoader(ObjectMapper yamlMapper) {
        this.yamlMapper = Objects.requireNonNull(yamlMapper, "yamlMapper must not be null");
    }

    @Override
    public PolicySet load(InputStream inputStream) throws InvalidPolicyException {
        if (inputStream == null) {
            throw new InvalidPolicyException("Cannot load policy: InputStream is null");
        }
        try {
            PolicyDocumentDto dto = yamlMapper.readValue(inputStream, PolicyDocumentDto.class);
            return compile(dto);
        } catch (JsonProcessingException e) {
            throw new InvalidPolicyException("Failed to parse YAML policy syntax: " + e.getOriginalMessage(), e);
        } catch (IOException e) {
            throw new InvalidPolicyException("I/O error while reading policy input stream: " + e.getMessage(), e);
        }
    }

    @Override
    public PolicySet load(String content) throws InvalidPolicyException {
        if (content == null || content.isBlank()) {
            throw new InvalidPolicyException("Cannot load policy: content is empty or blank");
        }
        try {
            PolicyDocumentDto dto = yamlMapper.readValue(content, PolicyDocumentDto.class);
            return compile(dto);
        } catch (JsonProcessingException e) {
            throw new InvalidPolicyException("Failed to parse YAML policy syntax: " + e.getOriginalMessage(), e);
        } catch (IOException e) {
            throw new InvalidPolicyException("I/O error while reading policy content: " + e.getMessage(), e);
        }
    }

    @Override
    public PolicySet load(File file) throws InvalidPolicyException {
        if (file == null || !file.exists() || !file.canRead()) {
            throw new InvalidPolicyException("Cannot load policy: file does not exist or is unreadable: " + file);
        }
        try (InputStream fis = new FileInputStream(file)) {
            return load(fis);
        } catch (IOException e) {
            throw new InvalidPolicyException("Failed to read policy file: " + file.getAbsolutePath(), e);
        }
    }

    /**
     * Compiles and validates the unmarshalled DTO into an immutable PolicySet.
     */
    public PolicySet compile(PolicyDocumentDto dto) throws InvalidPolicyException {
        if (dto == null) {
            throw new InvalidPolicyException("Policy document is null or empty");
        }

        // 1. Validate version
        if (dto.version() == null || (!dto.version().equals("1") && !dto.version().equals("1.0"))) {
            throw new InvalidPolicyException(
                "Unsupported policy version: '" + dto.version() + "'. Expected version '1' or '1.0'."
            );
        }

        // 2. Validate roles
        if (dto.roles() == null || dto.roles().isEmpty()) {
            throw new InvalidPolicyException("Policy validation error: 'roles' section must not be empty");
        }

        Map<String, RoleDefinition> compiledRoles = new HashMap<>();
        for (Map.Entry<String, RoleDto> entry : dto.roles().entrySet()) {
            String roleName = entry.getKey();
            RoleDto roleDto = entry.getValue();

            if (roleName == null || roleName.isBlank()) {
                throw new InvalidPolicyException("Role definition contains empty or blank role name");
            }
            if (roleDto == null || roleDto.permissions() == null || roleDto.permissions().isEmpty()) {
                throw new InvalidPolicyException("Role '" + roleName + "' must specify at least one permission");
            }

            Set<String> perms = new HashSet<>(roleDto.permissions());
            compiledRoles.put(
                roleName,
                RoleDefinition.of(roleName, roleDto.description(), perms)
            );
        }

        // 3. Validate rules
        List<PolicyRule> compiledRules = new ArrayList<>();
        if (dto.rules() != null) {
            for (RuleDto ruleDto : dto.rules()) {
                if (ruleDto.id() == null || ruleDto.id().isBlank()) {
                    throw new InvalidPolicyException("Policy rule is missing mandatory 'id'");
                }

                RuleEffect effect;
                try {
                    effect = RuleEffect.valueOf(ruleDto.effect().toUpperCase());
                } catch (IllegalArgumentException | NullPointerException e) {
                    throw new InvalidPolicyException(
                        "Invalid rule effect '" + ruleDto.effect() + "' on rule '" + ruleDto.id() +
                        "'. Must be one of: ALLOW, DENY, APPROVAL_REQUIRED"
                    );
                }

                PolicyRule.Builder builder = PolicyRule.builder(ruleDto.id(), effect);
                if (ruleDto.description() != null) {
                    builder.description(ruleDto.description());
                }

                if (ruleDto.target() != null) {
                    var target = ruleDto.target();
                    if (target.roles() != null && !target.roles().isEmpty()) {
                        builder.targetRoles(new HashSet<>(target.roles()));
                    }
                    if (target.actions() != null && !target.actions().isEmpty()) {
                        builder.targetActions(new HashSet<>(target.actions()));
                    }
                    if (target.resources() != null) {
                        if (target.resources().type() != null) {
                            builder.resourceType(target.resources().type());
                        }
                        if (target.resources().id() != null) {
                            builder.resourceId(target.resources().id());
                        }
                    }
                    if (target.conditions() != null && target.conditions().environment() != null) {
                        var envCond = target.conditions().environment();
                        Set<String> envs = new HashSet<>();
                        if (envCond.equals() != null && !envCond.equals().isBlank()) {
                            envs.add(envCond.equals());
                        }
                        if (envCond.in() != null) {
                            envs.addAll(envCond.in());
                        }
                        builder.environments(envs);
                    }
                }

                compiledRules.add(builder.build());
            }
        }

        String policyName = "agentguard-policy";
        if (dto.metadata() != null && dto.metadata().containsKey("name")) {
            policyName = String.valueOf(dto.metadata().get("name"));
        }

        return PolicySet.builder(policyName, dto.version())
            .roles(compiledRoles)
            .rules(compiledRules)
            .build();
    }
}
