package io.agentguard.policy.loader;

import io.agentguard.core.exception.InvalidPolicyException;
import io.agentguard.core.model.PolicySet;

import java.io.File;
import java.io.InputStream;

/**
 * Contract for loading and compiling declarative policy definitions into an immutable {@link PolicySet}.
 */
public interface PolicyLoader {

    /**
     * Loads and compiles policy definition from an {@link InputStream}.
     */
    PolicySet load(InputStream inputStream) throws InvalidPolicyException;

    /**
     * Loads and compiles policy definition from a raw string.
     */
    PolicySet load(String content) throws InvalidPolicyException;

    /**
     * Loads and compiles policy definition from a {@link File}.
     */
    PolicySet load(File file) throws InvalidPolicyException;
}
