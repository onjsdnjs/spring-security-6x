package io.springsecurity.springsecurity6x.security.core.adapter.auth;

import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.filter.OttForwardingFilter;
import io.springsecurity.springsecurity6x.security.service.ott.CodeStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

@Slf4j
public class OttAuthenticationAdapter extends AbstractAuthenticationAdapter<OttOptions> {

    @Override
    public String getId() {
        return AuthType.OTT.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 300; // 다른 인증 방식과의 순서
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, OttOptions options,
                                         AuthenticationSuccessHandler successHandler, // 이 메소드는 Ott에서는 사용 안 함
                                         AuthenticationFailureHandler failureHandler) throws Exception {
        throw new UnsupportedOperationException(
                "OttAuthenticationAdapter uses OneTimeTokenGenerationSuccessHandler. Call configureHttpSecurityForOtt instead."
        );
    }

    @Override
    public void configureHttpSecurityForOtt(HttpSecurity http, OttOptions opts,
                                            OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler, // 코드 생성 성공 핸들러
                                            AuthenticationFailureHandler failureHandler) throws Exception { // 코드 검증 실패 핸들러

        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        CodeStore store = applicationContext.getBean(CodeStore.class);
        ContextPersistence contextPersistence = null; // MFA용 ContextPersistence
        boolean isMfaFlow = false;

        // 현재 HttpSecurity 객체가 MFA 플로우에 대한 것인지 확인하는 로직 필요
        // 예: HttpSecurity 공유 객체나 현재 구성 중인 AuthenticationFlowConfig의 typeName을 확인
        io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig currentFlow =
                http.getSharedObject(io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig.class);

        if (currentFlow != null && "mfa".equalsIgnoreCase(currentFlow.getTypeName())) {
            isMfaFlow = true;
            contextPersistence = http.getSharedObject(ContextPersistence.class); // MFA 플로우에서 공유된 ContextPersistence 사용
            if (contextPersistence == null) {
                log.warn("OttAuthenticationAdapter: ContextPersistence is null for MFA flow. OttForwardingFilter might not work correctly with FactorContext.");
            }
        }

        // OttForwardingFilter의 GET 처리 URL은 opts.getLoginProcessingUrl()과 동일하게 설정
        // (단, Spring Security의 OneTimeTokenAuthenticationFilter가 POST만 처리한다고 가정)
        // 또는, 매직 링크 URL은 opts.getLoginProcessingUrl() + "?code=..." 이고,
        // 이 필터는 opts.getLoginProcessingUrl() (GET) 요청을 가로채도록 설정.
        // 그리고 실제 POST 처리는 동일한 opts.getLoginProcessingUrl() (POST)로 포워딩.
        String getRequestUrlForForwardingFilter = opts.getLoginProcessingUrl(); // 예: /login/ott 또는 /login/mfa-ott
        String postProcessingUrlForAuthFilter = opts.getLoginProcessingUrl();   // 이 URL로 자동 POST

        OttForwardingFilter ottForwardingFilter =
                new OttForwardingFilter(
                        store,
                        postProcessingUrlForAuthFilter, // 자동 POST를 보낼 실제 검증 URL (POST)
                        determineDefaultFailureUrl(opts), // 코드 consume 실패 시 리다이렉트 UI URL
                        getRequestUrlForForwardingFilter, // 이 필터가 가로챌 매직 링크 URL (GET)
                        opts.getUsernameParameter(), // 기본 "username"
                        opts.getTokenParameter(),    // 기본 "token"
                        isMfaFlow ? contextPersistence : null // MFA 플로우일 때만 ContextPersistence 전달
                );
        // OneTimeTokenAuthenticationFilter는 Spring Security의 oneTimeTokenLogin() DSL에 의해 추가됨.
        // OttForwardingFilter는 그 앞에 위치해야 함.
        http.addFilterBefore(ottForwardingFilter, AuthenticationFilter.class);

        // Spring Security의 표준 oneTimeTokenLogin DSL 설정
        http.oneTimeTokenLogin(ott -> {
            ott.defaultSubmitPageUrl(opts.getDefaultSubmitPageUrl()) // 사용자가 직접 코드 입력하는 페이지 (선택적)
                    .loginProcessingUrl(postProcessingUrlForAuthFilter) // 코드 "검증"을 처리할 POST URL
                    .showDefaultSubmitPage(opts.isShowDefaultSubmitPage())
                    .tokenGeneratingUrl(opts.getTokenGeneratingUrl()) // 코드 "생성/발송"을 처리할 POST URL (GenerateOneTimeTokenFilter가 처리)
                    .tokenService(opts.getOneTimeTokenService())
                    .tokenGenerationSuccessHandler(tokenGenerationSuccessHandler); // 코드 생성/발송 성공 핸들러
            // usernameParameter, tokenParameter는 OneTimeTokenLoginConfigurer에 기본값이 설정되어 있음 (username, token)
            // 만약 OttOptions에 이 파라미터 이름 설정이 있다면 여기서 ott.usernameParameter(), ott.tokenParameter()로 설정 가능
        });
        log.info("OttAuthenticationAdapter: Configured OttForwardingFilter for GET {} and OneTimeTokenLogin for POST {} (Generation at {})",
                getRequestUrlForForwardingFilter, postProcessingUrlForAuthFilter, opts.getTokenGeneratingUrl());
    }

    @Override
    protected String determineDefaultFailureUrl(OttOptions options) {
        // 기본 실패 URL (예: 이메일 입력 페이지로 리다이렉트)
        return "/loginOtt?error=ott_default_failure"; // 또는 AuthContextProperties 등에서 가져옴
    }
}
