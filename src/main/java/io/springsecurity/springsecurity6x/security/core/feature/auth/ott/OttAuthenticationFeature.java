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

    @Override
    protected void configureHttpSecurity(HttpSecurity http, OttOptions options,
                                         AuthenticationSuccessHandler successHandler, // 이 파라미터는 사용되지 않음
                                         AuthenticationFailureHandler failureHandler) throws Exception {
        // OttAuthenticationFeature는 OneTimeTokenGenerationSuccessHandler를 사용하므로 이 메소드는 호출되지 않아야 함.
        // 만약 호출된다면 설정 오류이므로 예외 발생.
        throw new UnsupportedOperationException(
                "OttAuthenticationFeature uses OneTimeTokenGenerationSuccessHandler, not AuthenticationSuccessHandler for its primary success path."
        );
    }

    // OneTimeTokenGenerationSuccessHandler를 받는 메소드를 오버라이드하여 실제 설정 수행
    @Override
    protected void configureHttpSecurity(HttpSecurity http, OttOptions opts,
                                         OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler,
                                         AuthenticationFailureHandler failureHandler) throws Exception {
        http.oneTimeTokenLogin(ott -> {
            ott.defaultSubmitPageUrl(opts.getDefaultSubmitPageUrl())
                    .loginProcessingUrl(opts.getLoginProcessingUrl()) // 사용자가 링크 클릭 시 토큰 검증 및 로그인 처리 URL
                    .showDefaultSubmitPage(opts.isShowDefaultSubmitPage()) // 토큰 입력 폼 페이지 표시 여부
                    .tokenGeneratingUrl(opts.getTokenGeneratingUrl()) // 클라이언트가 토큰 생성을 요청하는 URL
                    .tokenService(opts.getOneTimeTokenService()) // OneTimeTokenService 빈
                    .tokenGenerationSuccessHandler(tokenGenerationSuccessHandler); // 토큰 *생성* 성공 시 핸들러
        });
    }
}

