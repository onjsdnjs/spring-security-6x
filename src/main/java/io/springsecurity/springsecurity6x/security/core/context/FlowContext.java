package io.springsecurity.springsecurity6x.security.core.context;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public record FlowContext(AuthenticationFlowConfig flow, HttpSecurity http, PlatformContext context, PlatformConfig config) {
}

