package io.springsecurity.springsecurity6x.security.dsl.authentication;
import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.handler.AuthenticationHandlers;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 공통 DSL 추상 클래스
 */
public abstract class AbstractAuthenticationDsl implements AuthenticationDsl {
    protected AuthenticationHandlers authenticationHandlers;

    public void init(HttpSecurity http) {
        if (authenticationHandlers == null) {
            this.authenticationHandlers = http.getSharedObject(AuthenticationHandlers.class);
        }
    }

    public abstract void configure(HttpSecurity http) throws Exception;
}

