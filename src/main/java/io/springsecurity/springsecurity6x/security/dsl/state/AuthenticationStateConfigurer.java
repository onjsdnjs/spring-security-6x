package io.springsecurity.springsecurity6x.security.dsl.state;

import io.springsecurity.springsecurity6x.security.handler.authentication.AuthenticationHandlers;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 인증 상태 전략 공통 인터페이스 (JWT / Session)
 */
public interface AuthenticationStateConfigurer extends AuthenticationHandlers {

    void init(HttpSecurity http) throws Exception;

    void configure(HttpSecurity http) throws Exception;

    AuthenticationHandlers authHandlers();
}


