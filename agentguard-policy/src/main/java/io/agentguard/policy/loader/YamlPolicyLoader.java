package io.agentguard.policy.loader;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.agentguard.core.exception.InvalidPolicyException;
import io.agentguard.core.model.PolicyRule;
import io.agentguard.core.model.PolicySet;
import io.agentguard.core.model.RoleDefinition;
import io.agentguard.core.model.RuleEffect;
import io.agentguard.core.model.RiskLevel;
import io.agentguard.core.model.condition.ConditionOperator;
import io.agentguard.core.model.condition.RuleConditions;
import io.agentguard.policy.dto.ConditionsDto;
import io.agentguard.policy.dto.PolicyDocumentDto;
import io.agentguard.policy.dto.RoleDto;
import io.agentguard.policy.dto.RuleDto;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
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
        Set<String> ruleIds = new HashSet<>();
        if (dto.rules() != null) {
            for (RuleDto ruleDto : dto.rules()) {
                if (ruleDto.id() == null || ruleDto.id().isBlank()) {
                    throw new InvalidPolicyException("Policy rule is missing mandatory 'id'");
                }
                if (!ruleIds.add(ruleDto.id())) {
                    throw new InvalidPolicyException("Duplicate policy rule id: '" + ruleDto.id() + "'");
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
                if (ruleDto.risk() != null) {
                    try { builder.risk(RiskLevel.valueOf(ruleDto.risk().toUpperCase())); }
                    catch (IllegalArgumentException invalid) {
                        throw new InvalidPolicyException("Invalid risk '" + ruleDto.risk() + "' on rule '" + ruleDto.id()
                            + "'. Must be one of: LOW, MEDIUM, HIGH, CRITICAL");
                    }
                }
                if (ruleDto.description() != null) {
                    builder.description(ruleDto.description());
                }

                Set<String> environments = new HashSet<>();
                RuleConditions.Builder condBuilder = RuleConditions.builder();

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
                    if (target.conditions() != null) {
                        compileConditions(ruleDto.id(), target.conditions(), environments, condBuilder);
                    }
                }

                if (ruleDto.conditions() != null) {
                    compileConditions(ruleDto.id(), ruleDto.conditions(), environments, condBuilder);
                }

                if (!environments.isEmpty()) {
                    builder.environments(environments);
                }

                RuleConditions compiledConditions = condBuilder.build();
                if (!compiledConditions.isEmpty()) {
                    builder.conditions(compiledConditions);
                }

                compiledRules.add(builder.build());
            }
        }

        String policyName = "agentguard-policy";
        String policyVersion = dto.version();
        if (dto.metadata() != null && dto.metadata().containsKey("name")) {
            Object name = dto.metadata().get("name");
            if (!(name instanceof String text) || text.isBlank()) {
                throw new InvalidPolicyException("Policy metadata.name must be a non-blank string");
            }
            policyName = text;
        }
        if (dto.metadata() != null && dto.metadata().containsKey("version")) {
            Object declaredVersion = dto.metadata().get("version");
            if (!(declaredVersion instanceof String text) || text.isBlank()) {
                throw new InvalidPolicyException("Policy metadata.version must be a non-blank string");
            }
            policyVersion = text;
        }

        return PolicySet.builder(policyName, policyVersion)
            .roles(compiledRoles)
            .rules(compiledRules)
            .build();
    }

    private void compileConditions(
        String ruleId,
        ConditionsDto conditionsDto,
        Set<String> environmentsOut,
        RuleConditions.Builder condBuilder
    ) throws InvalidPolicyException {
        if (conditionsDto == null) return;

        // 1. Environment
        if (conditionsDto.environment() != null) {
            Object envObj = conditionsDto.environment();
            if (envObj instanceof Map<?, ?> map) {
                for (var entry : map.entrySet()) {
                    String opName = entry.getKey().toString();
                    ConditionOperator op = ConditionOperator.fromYaml(opName).orElseThrow(() ->
                        new InvalidPolicyException("Unsupported condition operator: '" + opName + "' on rule '" + ruleId + "'"));
                    condBuilder.environment(op, entry.getValue());
                    if (op == ConditionOperator.EQUALS && entry.getValue() != null) {
                        environmentsOut.add(entry.getValue().toString());
                    } else if (op == ConditionOperator.IN && entry.getValue() instanceof Collection<?> col) {
                        for (Object o : col) {
                            if (o != null) environmentsOut.add(o.toString());
                        }
                    }
                }
            } else if (envObj instanceof String s) {
                condBuilder.environment(ConditionOperator.EQUALS, s);
                environmentsOut.add(s);
            }
        }

        // 2. Tenant
        if (conditionsDto.tenant() != null) {
            Object tenantObj = conditionsDto.tenant();
            if (tenantObj instanceof Map<?, ?> map) {
                for (var entry : map.entrySet()) {
                    String opName = entry.getKey().toString();
                    ConditionOperator op = ConditionOperator.fromYaml(opName).orElseThrow(() ->
                        new InvalidPolicyException("Unsupported condition operator: '" + opName + "' on rule '" + ruleId + "'"));
                    condBuilder.tenant(op, entry.getValue());
                }
            } else if (tenantObj instanceof String s) {
                condBuilder.tenant(ConditionOperator.EQUALS, s);
            }
        }

        // 3. Arguments
        if (conditionsDto.arguments() != null) {
            for (var entry : conditionsDto.arguments().entrySet()) {
                String field = entry.getKey();
                Object val = entry.getValue();
                if (val instanceof Map<?, ?> opMap) {
                    for (var opEntry : opMap.entrySet()) {
                        String opName = opEntry.getKey().toString();
                        ConditionOperator op = ConditionOperator.fromYaml(opName).orElseThrow(() ->
                            new InvalidPolicyException("Unsupported condition operator: '" + opName + "' on rule '" + ruleId + "'"));
                        condBuilder.argument(field, op, opEntry.getValue());
                    }
                } else {
                    condBuilder.argument(field, ConditionOperator.EQUALS, val);
                }
            }
        }

        // 4. Subject
        if (conditionsDto.subject() != null) {
            for (var entry : conditionsDto.subject().entrySet()) {
                String key = entry.getKey();
                Object val = entry.getValue();
                if ("attributes".equalsIgnoreCase(key) && val instanceof Map<?, ?> attrs) {
                    for (var attrEntry : attrs.entrySet()) {
                        String attrName = attrEntry.getKey().toString();
                        Object attrVal = attrEntry.getValue();
                        if (attrVal instanceof Map<?, ?> opMap) {
                            for (var opEntry : opMap.entrySet()) {
                                String opName = opEntry.getKey().toString();
                                ConditionOperator op = ConditionOperator.fromYaml(opName).orElseThrow(() ->
                                    new InvalidPolicyException("Unsupported condition operator: '" + opName + "' on rule '" + ruleId + "'"));
                                condBuilder.subjectAttribute(attrName, op, opEntry.getValue());
                            }
                        } else {
                            condBuilder.subjectAttribute(attrName, ConditionOperator.EQUALS, attrVal);
                        }
                    }
                } else if (val instanceof Map<?, ?> opMap) {
                    for (var opEntry : opMap.entrySet()) {
                        String opName = opEntry.getKey().toString();
                        ConditionOperator op = ConditionOperator.fromYaml(opName).orElseThrow(() ->
                            new InvalidPolicyException("Unsupported condition operator: '" + opName + "' on rule '" + ruleId + "'"));
                        condBuilder.subjectField(key, op, opEntry.getValue());
                    }
                } else {
                    condBuilder.subjectField(key, ConditionOperator.EQUALS, val);
                }
            }
        }

        // 5. Attributes (top-level under conditions)
        if (conditionsDto.attributes() != null) {
            for (var entry : conditionsDto.attributes().entrySet()) {
                String attrName = entry.getKey();
                Object val = entry.getValue();
                if (val instanceof Map<?, ?> opMap) {
                    for (var opEntry : opMap.entrySet()) {
                        String opName = opEntry.getKey().toString();
                        ConditionOperator op = ConditionOperator.fromYaml(opName).orElseThrow(() ->
                            new InvalidPolicyException("Unsupported condition operator: '" + opName + "' on rule '" + ruleId + "'"));
                        condBuilder.subjectAttribute(attrName, op, opEntry.getValue());
                    }
                } else {
                    condBuilder.subjectAttribute(attrName, ConditionOperator.EQUALS, val);
                }
            }
        }

        // 6. Resource
        if (conditionsDto.resource() != null) {
            for (var entry : conditionsDto.resource().entrySet()) {
                String key = entry.getKey();
                Object val = entry.getValue();
                if (("tags".equalsIgnoreCase(key) || "attributes".equalsIgnoreCase(key)) && val instanceof Map<?, ?> tags) {
                    for (var tagEntry : tags.entrySet()) {
                        String tagName = tagEntry.getKey().toString();
                        Object tagVal = tagEntry.getValue();
                        if (tagVal instanceof Map<?, ?> opMap) {
                            for (var opEntry : opMap.entrySet()) {
                                String opName = opEntry.getKey().toString();
                                ConditionOperator op = ConditionOperator.fromYaml(opName).orElseThrow(() ->
                                    new InvalidPolicyException("Unsupported condition operator: '" + opName + "' on rule '" + ruleId + "'"));
                                condBuilder.resourceTag(tagName, op, opEntry.getValue());
                            }
                        } else {
                            condBuilder.resourceTag(tagName, ConditionOperator.EQUALS, tagVal);
                        }
                    }
                } else if (val instanceof Map<?, ?> opMap) {
                    for (var opEntry : opMap.entrySet()) {
                        String opName = opEntry.getKey().toString();
                        ConditionOperator op = ConditionOperator.fromYaml(opName).orElseThrow(() ->
                            new InvalidPolicyException("Unsupported condition operator: '" + opName + "' on rule '" + ruleId + "'"));
                        condBuilder.resourceField(key, op, opEntry.getValue());
                    }
                } else {
                    condBuilder.resourceField(key, ConditionOperator.EQUALS, val);
                }
            }
        }

        // 7. Context
        if (conditionsDto.context() != null) {
            for (var entry : conditionsDto.context().entrySet()) {
                String key = entry.getKey();
                Object val = entry.getValue();
                if (val instanceof Map<?, ?> opMap) {
                    for (var opEntry : opMap.entrySet()) {
                        String opName = opEntry.getKey().toString();
                        ConditionOperator op = ConditionOperator.fromYaml(opName).orElseThrow(() ->
                            new InvalidPolicyException("Unsupported condition operator: '" + opName + "' on rule '" + ruleId + "'"));
                        condBuilder.context(key, op, opEntry.getValue());
                    }
                } else {
                    condBuilder.context(key, ConditionOperator.EQUALS, val);
                }
            }
        }
    }
}
