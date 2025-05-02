package io.springsecurity.springsecurity6x.security.init.configurer;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 각 인증 방식의 설정 책임을 위임하는 인터페이스.
 */
public interface AuthConfigurer {
    void configure(HttpSecurity http) throws Exception;
}
