package io.springsecurity.springsecurity6x.security.core.context;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class FlowContext {
    private final AuthenticationFlowConfig flow;
    private final HttpSecurity http;

    public FlowContext(AuthenticationFlowConfig flow, HttpSecurity http) {
        this.flow = flow;
        this.http = http;
    }

    public AuthenticationFlowConfig flow() { return flow; }
    public HttpSecurity http() { return http; }
}

