package io.springsecurity.springsecurity6x.security.core.feature.auth.passkey;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.handler.MfaStepSuccessHandler;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.List;
import java.util.function.Supplier;

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

        AuthenticationStepConfig myStep = steps.stream()
                .filter(s -> AuthType.PASSKEY.name().equalsIgnoreCase(s.getType()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Passkey step config missing"));

        PasskeyOptions opts = (PasskeyOptions) myStep.getOptions().get("_options");
        int idx = steps.indexOf(myStep);
        boolean last = idx == steps.size() - 1;
        Supplier<TokenService> tokenSupplier = () ->
                http.getSharedObject(PlatformContext.class).getShared(TokenService.class);

        AuthenticationSuccessHandler orig = opts.getSuccessHandler() != null
                ? opts.getSuccessHandler()
                : http.getSharedObject(AuthenticationSuccessHandler.class);
        AuthenticationFailureHandler failure = opts.getFailureHandler();

        AuthenticationSuccessHandler handler = last
                ? MfaStepSuccessHandler.forTokenStep(tokenSupplier, orig)
                : MfaStepSuccessHandler.forAuthStep(steps, idx);


        // WebAuthn DSL 적용
        http.webAuthn(web -> web
                .rpName(opts.getRpName())
                .rpId(opts.getRpId())
                .allowedOrigins(opts.getAllowedOrigins())
        );
    }
}

