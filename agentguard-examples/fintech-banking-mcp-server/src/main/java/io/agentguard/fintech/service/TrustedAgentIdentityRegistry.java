package io.agentguard.fintech.service;

import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.identity.AgentIdentityLookup;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.AgentType;
import org.springframework.stereotype.Component;

import java.security.Principal;
import java.time.Instant;
import java.util.*;

/**
 * Enterprise identity registry for financial agents, compliance officers, and signers.
 * Implements AgentIdentityLookup to resolve cryptographic delegation parents without caller spoofing.
 */
@Component
public class TrustedAgentIdentityRegistry implements AgentIdentityLookup {

    private final Map<String, AgentIdentity> identities = new HashMap<>();

    public TrustedAgentIdentityRegistry() {
        Instant now = Instant.now();
        Instant validUntil = now.plusSeconds(86400);

        // 1. Executive CFO Identity (Parent signer for corporate treasury)
        AgentIdentity cfo = AgentIdentity.builder()
            .agentId("corporate-cfo")
            .agentType(AgentType.ASSISTANT)
            .role("corporate-cfo")
            .issuedAt(now.minusSeconds(60))
            .expiresAt(validUntil)
            .build();
        identities.put("corporate-cfo", cfo);

        // 2. Delegated Corporate Payroll Bot (Acts under CFO delegation chain)
        AgentIdentity payrollBot = AgentIdentity.builder()
            .agentId("payroll-bot")
            .agentType(AgentType.AUTONOMOUS)
            .role("corporate-finance-agent")
            .delegationChain(List.of("corporate-cfo"))
            .issuedAt(now)
            .expiresAt(validUntil.minusSeconds(60))
            .build();
        identities.put("payroll-bot", payrollBot);

        // 3. Automated Core Banking Agent
        AgentIdentity fintechBot = AgentIdentity.builder()
            .agentId("fintech-bot")
            .agentType(AgentType.AUTONOMOUS)
            .role("fintech-agent")
            .issuedAt(now)
            .expiresAt(validUntil)
            .build();
        identities.put("fintech-bot", fintechBot);

        // 4. Compliance Officer (AML / KYC Signer)
        AgentIdentity compliance = AgentIdentity.builder()
            .agentId("compliance-officer")
            .agentType(AgentType.ASSISTANT)
            .role("compliance-officer")
            .issuedAt(now)
            .expiresAt(validUntil)
            .build();
        identities.put("compliance-officer", compliance);

        // 5. API Platform Security Officer
        AgentIdentity security = AgentIdentity.builder()
            .agentId("security-officer")
            .agentType(AgentType.ASSISTANT)
            .role("security-officer")
            .issuedAt(now)
            .expiresAt(validUntil)
            .build();
        identities.put("security-officer", security);

        // 6. Low-privilege Guest Agent
        AgentIdentity guest = AgentIdentity.builder()
            .agentId("guest-agent")
            .agentType(AgentType.AUTONOMOUS)
            .role("guest-agent")
            .issuedAt(now)
            .expiresAt(validUntil)
            .build();
        identities.put("guest-agent", guest);
    }

    public AgentIdentity resolve(Principal principal) {
        if (principal == null || !identities.containsKey(principal.getName())) {
            throw new AgentAccessDeniedException("Authenticated agent principal required");
        }
        return identities.get(principal.getName());
    }

    @Override
    public Optional<AgentIdentity> find(String agentId) {
        return Optional.ofNullable(identities.get(agentId));
    }

    public Set<String> allAgentIds() {
        return Collections.unmodifiableSet(identities.keySet());
    }
}
