package io.agentguard.core.identity;

import io.agentguard.core.exception.AgentAuthenticationException;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.AgentType;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;

/**
 * Resolves verified AgentIdentity from SPIFFE Workload SVIDs.
 */
public final class SpiffeAgentIdentityResolver implements AgentIdentityResolver {
    private final Supplier<Optional<SpiffeSvid>> svidSupplier;
    private final Clock clock;

    public SpiffeAgentIdentityResolver(Supplier<Optional<SpiffeSvid>> svidSupplier) {
        this(svidSupplier, Clock.systemUTC());
    }

    public SpiffeAgentIdentityResolver(Supplier<Optional<SpiffeSvid>> svidSupplier, Clock clock) {
        this.svidSupplier = Objects.requireNonNull(svidSupplier, "svidSupplier");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public Optional<AgentIdentity> resolveCurrentIdentity() {
        Optional<SpiffeSvid> svidOpt = svidSupplier.get();
        if (svidOpt == null || svidOpt.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(resolve(svidOpt.get()));
    }

    public AgentIdentity resolve(SpiffeSvid svid) {
        Objects.requireNonNull(svid, "svid");
        Instant now = clock.instant();
        if (!now.isBefore(svid.expiresAt())) {
            throw new AgentAuthenticationException("SPIFFE SVID has expired: " + svid.spiffeId());
        }
        if (svid.issuedAt().isAfter(now.plusSeconds(60))) {
            throw new AgentAuthenticationException("SPIFFE SVID issuedAt is in the future: " + svid.spiffeId());
        }

        var builder = AgentIdentity.builder()
            .agentId(svid.spiffeId())
            .tenantId(svid.trustDomain())
            .agentType(AgentType.WORKER)
            .roles(svid.roles())
            .permissions(svid.permissions())
            .delegationChain(svid.delegationChain())
            .issuedAt(svid.issuedAt())
            .expiresAt(svid.expiresAt())
            .attribute("spiffe_trust_domain", svid.trustDomain());

        svid.attributes().forEach(builder::attribute);
        return builder.build();
    }
}

