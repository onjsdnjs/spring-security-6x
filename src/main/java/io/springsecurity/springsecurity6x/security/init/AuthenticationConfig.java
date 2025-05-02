package io.springsecurity.springsecurity6x.security.init;

import org.springframework.security.config.Customizer;

public record AuthenticationConfig(String type, Object options, String stateType, Customizer customizer) {}
