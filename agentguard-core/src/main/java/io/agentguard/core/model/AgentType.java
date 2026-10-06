package io.agentguard.core.model;

/**
 * Categorization of the AI agent runtime profile.
 * Distinguishes interactive chat assistants from autonomous background workers and system daemons.
 */
public enum AgentType {
    /**
     * User-facing interactive assistant executing on behalf of an active human prompt.
     */
    ASSISTANT,

    /**
     * Autonomous agent capable of multi-step planning, sub-task spawning, and loop execution.
     */
    AUTONOMOUS,

    /**
     * Task-bounded worker executing a single designated workflow.
     */
    WORKER,

    /**
     * Infrastructure or internal system maintenance agent.
     */
    SYSTEM
}
