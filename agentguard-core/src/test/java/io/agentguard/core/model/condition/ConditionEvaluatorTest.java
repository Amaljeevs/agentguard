package io.agentguard.core.model.condition;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.math.BigDecimal;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ConditionEvaluator Deterministic Operator Tests")
class ConditionEvaluatorTest {

    @Test
    void testExistsOperator() {
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.EXISTS, "non-null", true)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.EXISTS, null, true)).isFalse();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.EXISTS, null, false)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.EXISTS, 123, false)).isFalse();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.EXISTS, "val", "true")).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.EXISTS, null, "false")).isTrue();
    }

    @ParameterizedTest
    @CsvSource({
        "100, 100, true",
        "100.0, 100, true",
        "100.00, 100.0, true",
        "50000, 50000.00, true",
        "50000, 50001, false",
        "production, production, true",
        "production, staging, false",
        "true, true, true",
        "true, false, false"
    })
    void testEqualsAndNotEquals(String actual, String expected, boolean shouldEqual) {
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.EQUALS, actual, expected)).isEqualTo(shouldEqual);
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.NOT_EQUALS, actual, expected)).isEqualTo(!shouldEqual);
    }

    @Test
    void testNumericTypesEquals() {
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.EQUALS, 100, 100L)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.EQUALS, 100.0, new BigDecimal("100"))).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.EQUALS, 0, new BigDecimal("0.00"))).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.EQUALS, null, 100)).isFalse();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.NOT_EQUALS, null, 100)).isTrue();
    }

    @Test
    void testInAndNotInOperators() {
        List<String> envs = List.of("staging", "production");
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.IN, "production", envs)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.IN, "development", envs)).isFalse();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.IN, null, envs)).isFalse();

        assertThat(ConditionEvaluator.evaluate(ConditionOperator.NOT_IN, "development", envs)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.NOT_IN, "production", envs)).isFalse();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.NOT_IN, null, envs)).isTrue();

        List<Integer> allowedCodes = List.of(200, 201, 204);
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.IN, 200, allowedCodes)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.IN, 200.0, allowedCodes)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.IN, 404, allowedCodes)).isFalse();
    }

    @Test
    void testContainsOperator() {
        List<String> roles = List.of("admin", "treasury", "auditor");
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.CONTAINS, roles, "treasury")).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.CONTAINS, roles, "developer")).isFalse();

        Set<Integer> amounts = Set.of(100, 200, 500);
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.CONTAINS, amounts, 200.0)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.CONTAINS, amounts, 999)).isFalse();

        String path = "/api/v1/payments/disburse";
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.CONTAINS, path, "payments")).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.CONTAINS, path, "refunds")).isFalse();

        assertThat(ConditionEvaluator.evaluate(ConditionOperator.CONTAINS, null, "test")).isFalse();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.CONTAINS, path, null)).isFalse();
    }

    @Test
    void testNumericComparisons() {
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.GREATER_THAN, 50001, 50000)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.GREATER_THAN, 50000, 50000)).isFalse();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.GREATER_THAN, 49999, 50000)).isFalse();

        assertThat(ConditionEvaluator.evaluate(ConditionOperator.GREATER_THAN_OR_EQUAL, 50000, 50000)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.GREATER_THAN_OR_EQUAL, 50001, 50000)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.GREATER_THAN_OR_EQUAL, 49999, 50000)).isFalse();

        assertThat(ConditionEvaluator.evaluate(ConditionOperator.LESS_THAN, 49999, 50000)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.LESS_THAN, 50000, 50000)).isFalse();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.LESS_THAN, 50001, 50000)).isFalse();

        assertThat(ConditionEvaluator.evaluate(ConditionOperator.LESS_THAN_OR_EQUAL, 50000, 50000)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.LESS_THAN_OR_EQUAL, 49999, 50000)).isTrue();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.LESS_THAN_OR_EQUAL, 50001, 50000)).isFalse();

        // Non-numeric comparisons fail-closed to false
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.GREATER_THAN, "not-a-number", 50000)).isFalse();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.GREATER_THAN, 50000, "not-a-number")).isFalse();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.LESS_THAN, null, 50000)).isFalse();
        assertThat(ConditionEvaluator.evaluate(ConditionOperator.GREATER_THAN, null, 50000)).isFalse();
    }
}

