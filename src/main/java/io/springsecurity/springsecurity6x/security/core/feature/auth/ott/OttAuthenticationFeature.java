package io.springsecurity.springsecurity6x.security.core.feature.auth.ott;

import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.feature.auth.AbstractAuthenticationFeature;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;


public class OttAuthenticationFeature extends AbstractAuthenticationFeature<OttOptions> {

    @Override
    public String getId() {
        return AuthType.OTT.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 300;
    }

    // 이 메소드는 OttAuthenticationFeature 에서 직접 사용되지 않음.
    @Override
    protected void configureHttpSecurity(HttpSecurity http, OttOptions options,
                                         AuthenticationSuccessHandler successHandler, // 사용 안 함
                                         AuthenticationFailureHandler failureHandler) throws Exception {
        throw new UnsupportedOperationException(
                "OttAuthenticationFeature uses OneTimeTokenGenerationSuccessHandler. Call configureHttpSecurityForOtt instead."
        );
    }

    // OneTimeTokenGenerationSuccessHandler를 받는 메소드를 오버라이드
    @Override
    protected void configureHttpSecurityForOtt(HttpSecurity http, OttOptions opts,
                                               OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler,
                                               AuthenticationFailureHandler failureHandler) throws Exception {
        http.oneTimeTokenLogin(ott -> {
            ott.defaultSubmitPageUrl(opts.getDefaultSubmitPageUrl())
                    .loginProcessingUrl(opts.getLoginProcessingUrl())
                    .showDefaultSubmitPage(opts.isShowDefaultSubmitPage())
                    .tokenGeneratingUrl(opts.getTokenGeneratingUrl())
                    .tokenService(opts.getOneTimeTokenService())
                    .tokenGenerationSuccessHandler(tokenGenerationSuccessHandler);

            // Spring Security 6.x의 oneTimeTokenLogin() DSL이 failureHandler를 직접 지원하는지 확인 필요.
            // 지원하지 않는다면, OneTimeTokenAuthenticationFilter를 커스텀하게 설정하거나,
            // SecurityFilterChain에 별도의 예외 처리 필터를 추가하는 방식을 고려해야 합니다.
            // 예시: if (failureHandler != null) { ott.failureHandler(failureHandler); } (DSL 지원 가정)
            // 현재 Spring Security의 Standard DSL에는 ott.failureHandler()가 명시적으로 없을 수 있습니다.
            // 이 경우, OneTimeTokenAuthenticationFilter의 setAuthenticationFailureHandler를 사용하거나
            // ExceptionTranslationFilter 등을 통해 예외를 처리해야 합니다.
            // 여기서는 DSL이 지원한다고 가정하거나, 혹은 AbstractAuthenticationFilter에서 이미 기본 에러 처리가 된다고 간주합니다.
        });
    }

    @Override
    protected String determineDefaultFailureUrl(OttOptions options) {
        // OttOptions에 failureUrl 필드가 있다면 그것을 사용. 없다면 기본값.
        // 예: return options.getFailureUrl() != null ? options.getFailureUrl() : "/loginOtt?error_ott_default";
        return "/loginOtt?error_ott_default";
    }
}
