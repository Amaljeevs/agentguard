package io.agentguard.web.api;

import org.springframework.web.bind.annotation.*;

/** Optional HTTP adapter; the core Java engine remains embeddable without Spring MVC. */
@RestController
@RequestMapping("/v1")
public final class AuthorizationController {
    private final AgentGuardAuthorizationApi api;
    public AuthorizationController(AgentGuardAuthorizationApi api) { this.api = api; }

    @PostMapping(path = "/authorize", consumes = "application/json", produces = "application/json")
    public AuthorizationApiResponse authorize(@RequestBody AuthorizationApiRequest request) {
        return api.authorize(request);
    }
}
