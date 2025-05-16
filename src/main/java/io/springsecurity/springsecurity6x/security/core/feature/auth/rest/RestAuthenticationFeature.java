package io.springsecurity.springsecurity6x.security.core.feature.auth.rest;

import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.RestAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.feature.auth.AbstractAuthenticationFeature;
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

            // mfaInitiateUrl 설정은 RestAuthenticationConfigurer 내부에서
            // PlatformContext나 AuthContextProperties를 통해 가져오도록 하는 것이 더 깔끔할 수 있습니다.
            // 현재 AbstractAuthenticationFeature 에서는 이 부분을 직접 다루지 않습니다.
            // 필요하다면 options 객체에 mfaInitiateUrl을 포함시키거나,
            // AbstractAuthenticationFeature의 apply 메소드에서 appContext를 통해 설정할 수 있습니다.
        });
    }

    // REST API의 경우, AbstractAuthenticationFeature의 determineDefaultFailureUrl이
    // SimpleUrlAuthenticationFailureHandler를 생성하므로, JSON 오류 응답을 보내는
    // 기본 실패 핸들러를 사용하도록 apply 메소드에서 직접 설정했습니다.
    // 따라서 이 메소드는 호출되지 않거나, 호출되더라도 REST에 적합한 URL을 반환하지 않을 수 있습니다.
    // AbstractAuthenticationFeature의 apply 메소드에서 failureHandler가 null일 때
    // REST 타입에 대한 특별 처리가 이미 추가되었습니다.
}

