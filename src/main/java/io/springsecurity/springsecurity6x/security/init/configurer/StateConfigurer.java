package io.springsecurity.springsecurity6x.security.init.configurer;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 상태 유지 전략 설정을 추상화한 공통 인터페이스
 */
public interface StateConfigurer {
    void apply(HttpSecurity http) throws Exception;
}
