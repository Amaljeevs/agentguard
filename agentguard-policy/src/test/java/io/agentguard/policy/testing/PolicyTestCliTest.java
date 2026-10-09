package io.agentguard.policy.testing;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.file.*;
import static org.assertj.core.api.Assertions.*;

class PolicyTestCliTest {
    @TempDir Path directory;
    @Test void mismatchesReturnNonzeroAndReportDecisionExplanation() throws Exception {
        Path policy = directory.resolve("policy.yaml"); Path cases = directory.resolve("cases.json");
        Files.writeString(policy, "version: '1.0'\nroles:\n  reader:\n    permissions: [orders.read]\n");
        Files.writeString(cases, """
            [{"name":"blocked","agentId":"a","roles":["reader"],"action":"orders.delete",
              "resourceType":"order","resourceId":"1","environment":"production","expected":"ALLOW"}]
            """);
        var output = new ByteArrayOutputStream();
        assertThat(PolicyTestCli.run(new String[]{policy.toString(), cases.toString()}, new PrintStream(output))).isEqualTo(1);
        assertThat(output.toString()).contains("FAIL blocked: DENY", "Policy revision:");
        Files.writeString(cases, Files.readString(cases).replace("\"ALLOW\"", "\"DENY\""));
        assertThat(PolicyTestCli.run(new String[]{policy.toString(), cases.toString()}, new PrintStream(output))).isZero();
    }
}
