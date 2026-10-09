package io.agentguard.core.engine;

import io.agentguard.core.model.PolicySet;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HexFormat;

/** Stable fingerprint of policy contents, independent of map/set iteration order. */
public final class PolicyRevision {
    private PolicyRevision() {}

    public static String of(PolicySet policy) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            add(digest, policy.name());
            add(digest, policy.version());
            policy.roles().entrySet().stream().sorted(java.util.Map.Entry.comparingByKey()).forEach(entry -> {
                add(digest, "role");
                add(digest, entry.getKey());
                sorted(digest, entry.getValue().permissions());
            });
            // Rule order affects which matching explanation is returned, so preserve it.
            policy.rules().forEach(rule -> {
                add(digest, "rule"); add(digest, rule.id()); add(digest, rule.effect().name());
                add(digest, rule.description().orElse(""));
                sorted(digest, rule.targetRoles()); sorted(digest, rule.targetActions());
                add(digest, rule.resourceType().orElse("")); add(digest, rule.resourceId().orElse(""));
                sorted(digest, rule.environments());
            });
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static void sorted(MessageDigest digest, Collection<String> values) {
        add(digest, Integer.toString(values.size()));
        values.stream().sorted().forEach(value -> add(digest, value));
    }

    private static void add(MessageDigest digest, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(java.nio.ByteBuffer.allocate(4).putInt(bytes.length).array());
        digest.update(bytes);
    }
}
