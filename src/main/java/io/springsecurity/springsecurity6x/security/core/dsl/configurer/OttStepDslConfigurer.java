package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

// StepDslConfigurer와 OptionsBuilderDsl을 확장
public interface OttStepDslConfigurer extends StepDslConfigurer, OptionsBuilderDsl<OttOptions, OttStepDslConfigurer> {
    OttStepDslConfigurer loginProcessingUrl(String url);
    OttStepDslConfigurer targetUrl(String url); // 성공 시 리다이렉트 또는 다음 단계 URL
    OttStepDslConfigurer defaultSubmitPageUrl(String url);
    OttStepDslConfigurer tokenGeneratingUrl(String url);
    OttStepDslConfigurer showDefaultSubmitPage(boolean show);
    OttStepDslConfigurer tokenService(OneTimeTokenService service);
    OttStepDslConfigurer tokenServiceBeanName(String beanName);
    OttStepDslConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler);
}