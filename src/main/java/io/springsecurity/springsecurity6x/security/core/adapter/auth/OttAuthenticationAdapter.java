package io.springsecurity.springsecurity6x.security.core.adapter.auth;

import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;


public class OttAuthenticationAdapter extends AbstractAuthenticationAdapter<OttOptions> {

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
    public void configureHttpSecurityForOtt(HttpSecurity http, OttOptions opts,
                                               OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler,
                                               AuthenticationFailureHandler failureHandler) throws Exception {
        http.oneTimeTokenLogin(ott -> {
            ott.defaultSubmitPageUrl(opts.getDefaultSubmitPageUrl())
                    .loginProcessingUrl(opts.getLoginProcessingUrl())
                    .showDefaultSubmitPage(opts.isShowDefaultSubmitPage())
                    .tokenGeneratingUrl(opts.getTokenGeneratingUrl())
                    .tokenService(opts.getOneTimeTokenService())
                    .tokenGenerationSuccessHandler(tokenGenerationSuccessHandler);
        });
    }

    @Override
    protected String determineDefaultFailureUrl(OttOptions options) {
        // OttOptions에 failureUrl 필드가 있다면 그것을 사용. 없다면 기본값.
        // 예: return options.getFailureUrl() != null ? options.getFailureUrl() : "/loginOtt?error_ott_default";
        return "/loginOtt?error_ott_default";
    }
}
