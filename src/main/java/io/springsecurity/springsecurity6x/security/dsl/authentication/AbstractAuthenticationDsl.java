package io.springsecurity.springsecurity6x.security.dsl.authentication;
import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateStrategy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 공통 DSL 추상 클래스
 */
public abstract class AbstractAuthenticationDsl {
    protected AuthenticationStateStrategy stateStrategy;

    public void init(HttpSecurity http) {
        this.stateStrategy = http.getSharedObject(AuthenticationStateStrategy.class);
    }

    public abstract void configure(HttpSecurity http) throws Exception;
}

