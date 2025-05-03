package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.option.PasskeyOptions;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Passkey(WebAuthn) 로그인 전략을 HttpSecurity에 적용하는 AuthenticationFeature 구현체입니다.
 *
 * DSL로 설정된 PasskeyOptions를 읽어서:
 *  - URL 매처(matchers)
 *  - RP 이름 및 ID(rpName, rpId)
 *  - 허용된 출처(allowedOrigins)
 * 등을 설정합니다.
 */
public class PasskeyAuthenticationFeature implements AuthenticationFeature {

    @Override
    public String getId() {
        return "passkey";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {
        // 1) 현재 AuthenticationConfig와 PasskeyOptions 꺼내오기
        AuthenticationConfig config = ctx.getShared(AuthenticationConfig.class);
        PasskeyOptions opts = (PasskeyOptions) config.options();

        // 2) 요청 매처 설정 (없으면 /** 전체)
        if (opts.getMatchers() != null && !opts.getMatchers().isEmpty()) {
            http.securityMatcher(opts.getMatchers().toArray(new String[0]));
        } else {
            http.securityMatcher("/**");
        }

        // 3) WebAuthn DSL 적용
        http.webAuthn(web -> web
                .rpName(opts.getRpName())
                .rpId(opts.getRpId())
                .allowedOrigins(opts.getAllowedOrigins())
        );
    }
}
