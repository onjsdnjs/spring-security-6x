package io.springsecurity.springsecurity6x.security.core.feature.auth;

import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.RestAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class RestAuthenticationFeature extends AbstractAuthenticationFeature<RestOptions> {

    @Override
    public String getId() {
        return AuthType.REST.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 200;
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, RestOptions opts,
                                         AuthenticationSuccessHandler successHandler,
                                         AuthenticationFailureHandler failureHandler) throws Exception {
        http.with(new RestAuthenticationConfigurer(), rest -> {
            rest.loginProcessingUrl(opts.getLoginProcessingUrl())
                    .successHandler(successHandler)
                    .failureHandler(failureHandler);

            if (opts.getSecurityContextRepository() != null) {
                rest.securityContextRepository(opts.getSecurityContextRepository());
            }
            // mfaInitiateUrl 설정은 RestAuthenticationConfigurer 내부에서 처리하거나,
            // AbstractAuthenticationFeature의 apply 또는 여기서 명시적으로 PlatformContext를 통해 주입
        });
    }

    // determineDefaultFailureUrl은 AbstractAuthenticationFeature에서 이미 REST 타입에 대해
    // JSON 오류 핸들러를 생성하도록 createDefaultFailureHandler 메소드가 수정되었으므로,
    // 여기서 특별히 오버라이드할 필요가 없을 수 있습니다.
    // 만약 다른 기본 URL이 필요하다면 오버라이드합니다.
    // @Override
    // protected String determineDefaultFailureUrl(RestOptions options) {
    //     return null; // REST는 URL 리다이렉션이 아닌 JSON 응답을 하므로, 이 메소드가 직접 사용되지 않음
    // }
}

