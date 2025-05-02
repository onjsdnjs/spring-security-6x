package io.springsecurity.springsecurity6x.security.build;

import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface IdentitySecurityConfigurer {

    boolean supports(AuthenticationConfig config);

    void configure(HttpSecurity http, AuthenticationConfig config) throws Exception;

    default int order() { return 0; }
}