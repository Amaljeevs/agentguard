package io.agentguard.core.security;

import io.agentguard.core.model.*;
import org.junit.jupiter.api.Test;
import java.math.BigDecimal;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class RequestFingerprintTest {
    @Test void canonicalHashIgnoresMapOrderAndNormalizesNumbersButBindsMeaningfulChanges() {
        var first = new LinkedHashMap<String,Object>(); first.put("b", 1); first.put("a", new BigDecimal("2.00"));
        var second = new LinkedHashMap<String,Object>(); second.put("a", 2); second.put("b", new BigDecimal("1.0"));
        assertThat(RequestFingerprint.argumentsHash(first)).isEqualTo(RequestFingerprint.argumentsHash(second));
        assertThat(RequestFingerprint.argumentsHash(Map.of("a", 3))).isNotEqualTo(RequestFingerprint.argumentsHash(second));
    }

    @Test void cyclesAndUnsupportedObjectsFailClosed() {
        Map<String,Object> cyclic = new HashMap<>(); cyclic.put("self", cyclic);
        assertThatThrownBy(() -> RequestFingerprint.argumentsHash(cyclic)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RequestFingerprint.argumentsHash(Map.of("unsafe", new Object())))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
