package io.agentguard.core.security;

import io.agentguard.core.model.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("RequestFingerprint Canonicalization & Edge-Case Tests")
class RequestFingerprintTest {

    record TransactionRecord(String accountId, BigDecimal amount, String currency) {}

    @Test
    void testMapKeyOrderingIndependence() {
        var map1 = new LinkedHashMap<String, Object>();
        map1.put("z_last", "foo");
        map1.put("a_first", "bar");
        map1.put("m_middle", 123);

        var map2 = new LinkedHashMap<String, Object>();
        map2.put("a_first", "bar");
        map2.put("m_middle", 123);
        map2.put("z_last", "foo");

        assertThat(RequestFingerprint.argumentsHash(map1))
            .isEqualTo(RequestFingerprint.argumentsHash(map2));
    }

    @Test
    void testNestedMapKeyOrdering() {
        var nested1 = new LinkedHashMap<String, Object>();
        nested1.put("user", Map.of("email", "dev@bank.com", "id", "USR-1"));
        nested1.put("details", new LinkedHashMap<>(Map.of("b", 2, "a", 1)));

        var nested2 = new LinkedHashMap<String, Object>();
        nested2.put("details", new LinkedHashMap<>(Map.of("a", 1, "b", 2)));
        nested2.put("user", Map.of("id", "USR-1", "email", "dev@bank.com"));

        assertThat(RequestFingerprint.argumentsHash(nested1))
            .isEqualTo(RequestFingerprint.argumentsHash(nested2));
    }

    @Test
    void testRecordFingerprinting() {
        var rec1 = new TransactionRecord("ACC-100", new BigDecimal("5000.00"), "USD");
        var rec2 = new TransactionRecord("ACC-100", new BigDecimal("5000.0"), "USD");

        String hash1 = RequestFingerprint.argumentsHash(Map.of("tx", rec1));
        String hash2 = RequestFingerprint.argumentsHash(Map.of("tx", rec2));

        assertThat(hash1).isEqualTo(hash2);

        var recDiff = new TransactionRecord("ACC-101", new BigDecimal("5000.00"), "USD");
        assertThat(RequestFingerprint.argumentsHash(Map.of("tx", recDiff))).isNotEqualTo(hash1);
    }

    @Test
    void testListAndArrayCanonicalization() {
        List<Object> list = List.of("alpha", 100, true);
        Object[] array = new Object[]{"alpha", 100, true};

        String hashList = RequestFingerprint.argumentsHash(Map.of("items", list));
        String hashArray = RequestFingerprint.argumentsHash(Map.of("items", array));

        assertThat(hashList).isEqualTo(hashArray);

        // Different ordering in list must produce different hash!
        List<Object> reversed = List.of(true, 100, "alpha");
        assertThat(RequestFingerprint.argumentsHash(Map.of("items", reversed))).isNotEqualTo(hashList);
    }

    @Test
    void testNumericNormalization() {
        // Integer, Long, Double, BigDecimal normalization
        var m1 = Map.of("amount", 100);
        var m2 = Map.of("amount", 100L);
        var m3 = Map.of("amount", 100.0);
        var m4 = Map.of("amount", 100.00);
        var m5 = Map.of("amount", new BigDecimal("100.000"));

        String h1 = RequestFingerprint.argumentsHash(m1);
        assertThat(RequestFingerprint.argumentsHash(m2)).isEqualTo(h1);
        assertThat(RequestFingerprint.argumentsHash(m3)).isEqualTo(h1);
        assertThat(RequestFingerprint.argumentsHash(m4)).isEqualTo(h1);
        assertThat(RequestFingerprint.argumentsHash(m5)).isEqualTo(h1);

        // Zero variants
        var z1 = Map.of("zero", 0);
        var z2 = Map.of("zero", 0L);
        var z3 = Map.of("zero", 0.0);
        var z4 = Map.of("zero", new BigDecimal("0.00"));
        String hz1 = RequestFingerprint.argumentsHash(z1);
        assertThat(RequestFingerprint.argumentsHash(z2)).isEqualTo(hz1);
        assertThat(RequestFingerprint.argumentsHash(z3)).isEqualTo(hz1);
        assertThat(RequestFingerprint.argumentsHash(z4)).isEqualTo(hz1);
    }

    @Test
    void testNullHandling() {
        Map<String, Object> withNull = new HashMap<>();
        withNull.put("present", "value");
        withNull.put("nullable", null);

        String hash = RequestFingerprint.argumentsHash(withNull);
        assertThat(hash).isNotNull().hasSize(64);

        Map<String, Object> withoutNull = Map.of("present", "value");
        // Distinguishes explicit null from missing field
        assertThat(RequestFingerprint.argumentsHash(withoutNull)).isNotEqualTo(hash);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "Transfer to José Müller",
        "مرحبا بالعالم",
        "こんにちは世界",
        "Special characters: !@#$%^&*()_+{}[]:;\"'<>?,./~`",
        "Emoji: 🛡️🔒💸💰"
    })
    void testUnicodeHandling(String text) {
        String hash1 = RequestFingerprint.argumentsHash(Map.of("memo", text));
        String hash2 = RequestFingerprint.argumentsHash(Map.of("memo", text));
        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    void testBooleans() {
        String hTrue = RequestFingerprint.argumentsHash(Map.of("flag", true));
        String hFalse = RequestFingerprint.argumentsHash(Map.of("flag", false));
        assertThat(hTrue).isNotEqualTo(hFalse);
    }

    @Test
    void testUnsupportedObjectsFailClosedWithoutToString() {
        class CustomUnsafeObject {
            @Override
            public String toString() {
                return "pretending-to-be-safe";
            }
        }

        assertThatThrownBy(() -> RequestFingerprint.argumentsHash(Map.of("unsafe", new CustomUnsafeObject())))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Fingerprint values must be JSON-compatible");
    }

    @Test
    void testCyclicStructuresFailClosed() {
        Map<String, Object> cyclic = new HashMap<>();
        cyclic.put("cycle", cyclic);

        assertThatThrownBy(() -> RequestFingerprint.argumentsHash(cyclic))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Fingerprint input contains a cycle");
    }

    @Test
    void testDepthLimitEnforced() {
        Map<String, Object> root = new HashMap<>();
        Map<String, Object> current = root;
        for (int i = 0; i < 35; i++) {
            Map<String, Object> next = new HashMap<>();
            current.put("child", next);
            current = next;
        }

        assertThatThrownBy(() -> RequestFingerprint.argumentsHash(root))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Fingerprint input exceeds maximum depth");
    }

    @Test
    void testItemLimitEnforced() {
        Map<String, Object> largeMap = new HashMap<>();
        for (int i = 0; i < 1005; i++) {
            largeMap.put("key_" + i, i);
        }

        assertThatThrownBy(() -> RequestFingerprint.argumentsHash(largeMap))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Fingerprint input has too many entries");

        List<Integer> largeList = new ArrayList<>();
        for (int i = 0; i < 1005; i++) {
            largeList.add(i);
        }

        assertThatThrownBy(() -> RequestFingerprint.argumentsHash(Map.of("list", largeList)))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Fingerprint input has too many items");
    }

    @Test
    void testEquivalentAndMateriallyDifferentRequests() {
        Instant fixed = Instant.parse("2026-10-13T10:00:00Z");

        AgentIdentity subject1 = AgentIdentity.builder()
            .agentId("agent-finance")
            .agentType(AgentType.AUTONOMOUS)
            .role("payment-agent")
            .issuedAt(fixed)
            .expiresAt(fixed.plusSeconds(3600))
            .attributes(Map.of("tenant", "corp-1"))
            .build();

        AgentIdentity subject2 = AgentIdentity.builder()
            .agentId("agent-finance")
            .agentType(AgentType.AUTONOMOUS)
            .role("payment-agent")
            .issuedAt(fixed)
            .expiresAt(fixed.plusSeconds(3600))
            .attributes(Map.of("tenant", "corp-1"))
            .build();

        AuthorizationRequest req1 = AuthorizationRequest.of(
            subject1,
            Action.of("payments.transfer", Map.of("amount", 5000, "to", "ACC-99")),
            Resource.of("account", "ACC-10"),
            AuthorizationContext.of("production")
        );

        AuthorizationRequest req2 = AuthorizationRequest.of(
            subject2,
            Action.of("payments.transfer", Map.of("to", "ACC-99", "amount", 5000.0)),
            Resource.of("account", "ACC-10"),
            AuthorizationContext.of("production")
        );

        // Identical fingerprint
        assertThat(RequestFingerprint.requestHash(req1)).isEqualTo(RequestFingerprint.requestHash(req2));

        // Materially different amount -> different fingerprint
        AuthorizationRequest reqDifferentAmount = AuthorizationRequest.of(
            subject1,
            Action.of("payments.transfer", Map.of("amount", 5001, "to", "ACC-99")),
            Resource.of("account", "ACC-10"),
            AuthorizationContext.of("production")
        );
        assertThat(RequestFingerprint.requestHash(reqDifferentAmount))
            .isNotEqualTo(RequestFingerprint.requestHash(req1));

        // Materially different destination -> different fingerprint
        AuthorizationRequest reqDifferentTo = AuthorizationRequest.of(
            subject1,
            Action.of("payments.transfer", Map.of("amount", 5000, "to", "ACC-ATTACKER")),
            Resource.of("account", "ACC-10"),
            AuthorizationContext.of("production")
        );
        assertThat(RequestFingerprint.requestHash(reqDifferentTo))
            .isNotEqualTo(RequestFingerprint.requestHash(req1));
    }
}
