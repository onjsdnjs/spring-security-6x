package io.springsecurity.springsecurity6x.security.core.dsl;

public interface OttDslConfigurer extends CommonSecurityDsl<OttDslConfigurer> {

    OttDslConfigurer matchers(String... patterns);

    OttDslConfigurer loginProcessingUrl(String url);

    // 추가된 DSL 메서드들
    OttDslConfigurer defaultSubmitPageUrl(String url);

    OttDslConfigurer tokenGeneratingUrl(String url);

    OttDslConfigurer showDefaultSubmitPage(boolean show);

    OttDslConfigurer tokenService(org.springframework.security.authentication.ott.OneTimeTokenService service);

    OttDslConfigurer tokenGenerationSuccessHandler(org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler handler);
}

