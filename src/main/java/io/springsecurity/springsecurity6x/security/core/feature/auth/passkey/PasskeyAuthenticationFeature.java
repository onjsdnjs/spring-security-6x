package io.springsecurity.springsecurity6x.security.core.feature.auth.passkey;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

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
    public int getOrder() {
        return 400;
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> steps, StateConfig state) throws Exception {
        // 단계 설정이 없으면 종료
        if (steps == null || steps.isEmpty()) {
            return;
        }
        AuthenticationStepConfig step = steps.getFirst();

        // 옵션 객체 추출
        Object optsObj = step.options().get("_options");
        if (!(optsObj instanceof PasskeyOptions)) {
            throw new IllegalStateException("Expected PasskeyOptions in step options");
        }
        PasskeyOptions opts = (PasskeyOptions) optsObj;

        // URL 매처 설정 (없으면 기본 매처 유지)
        if (opts.getMatchers() != null && !opts.getMatchers().isEmpty()) {
            http.securityMatcher(opts.getMatchers().toArray(new String[0]));
        }

        // WebAuthn DSL 적용
        http.webAuthn(web -> web
                .rpName(opts.getRpName())
                .rpId(opts.getRpId())
                .allowedOrigins(opts.getAllowedOrigins())
        );
    }
}

