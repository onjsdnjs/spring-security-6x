package io.springsecurity.springsecurity6x.security.dsl.state;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 인증 상태 전략 공통 인터페이스 (JWT / Session)
 */
public interface AuthenticationStateStrategy {
    void init(HttpSecurity http) throws Exception;
    void configure(HttpSecurity http) throws Exception;
}


