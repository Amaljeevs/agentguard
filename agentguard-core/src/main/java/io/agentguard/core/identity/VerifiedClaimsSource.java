package io.agentguard.core.identity;

import java.util.Optional;

/** Adapter SPI for verified Keycloak, Entra, SPIFFE-JWT or custom provider claims. */
@FunctionalInterface
public interface VerifiedClaimsSource {
    Optional<VerifiedClaims> current();
}
