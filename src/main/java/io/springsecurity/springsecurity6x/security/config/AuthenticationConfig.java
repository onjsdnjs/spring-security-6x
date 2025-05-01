package io.springsecurity.springsecurity6x.security.config;

import io.springsecurity.springsecurity6x.security.dsl.option.DslOptions;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class AuthenticationConfig {

    public String type; // 인증 방식: form, rest, passkey, ott
    public DslOptions options; // 각 방식별 DSL 설정 옵션들
    public String stateType; // 세션 기반인지 JWT 기반인지: session or jwt
    private Customizer<HttpSecurity> httpCustomizer; // 선택적 사용자 커스터마이저

    public Customizer<HttpSecurity> httpCustomizer() {
        return httpCustomizer;
    }

    public void httpCustomizer(Customizer<HttpSecurity> httpCustomizer) {
        this.httpCustomizer = httpCustomizer;
    }
}
