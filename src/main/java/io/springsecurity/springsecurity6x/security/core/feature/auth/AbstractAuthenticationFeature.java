package io.springsecurity.springsecurity6x.security.core.feature.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.auth.ott.OttAuthenticationFeature;
import io.springsecurity.springsecurity6x.security.handler.MfaCapableRestSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaStepBasedSuccessHandler;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;

import java.util.List;
import java.util.Map;
import java.util.Objects;

public abstract class AbstractAuthenticationFeature<O extends AuthenticationProcessingOptions> implements AuthenticationFeature {

    private static final Logger log = LoggerFactory.getLogger(AbstractAuthenticationFeature.class);

    @Override
    public abstract String getId();

    @Override
    public abstract int getOrder();

    protected abstract void configureHttpSecurity(HttpSecurity http, O options,
                                                  AuthenticationSuccessHandler successHandler,
                                                  AuthenticationFailureHandler failureHandler) throws Exception;

    protected void configureHttpSecurityForOtt(HttpSecurity http, O options,
                                               OneTimeTokenGenerationSuccessHandler ottSuccessHandler,
                                               AuthenticationFailureHandler failureHandler) throws Exception {
        if (!(this instanceof OttAuthenticationFeature)) {
            throw new UnsupportedOperationException(
                    String.format("Feature %s is not an OTT feature and should not call configureHttpSecurityForOtt by default.", getId())
            );
        }
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> allStepsInCurrentFlow, StateConfig stateConfig) throws Exception {
        AuthenticationStepConfig myRelevantStepConfig = null;
        if (allStepsInCurrentFlow != null) {
            for (AuthenticationStepConfig step : allStepsInCurrentFlow) {
                // getId()는 현재 Feature의 ID (예: "form", "rest")
                // step.getType()은 해당 스텝의 타입 (예: "form", "rest")
                if (getId().equalsIgnoreCase(step.getType())) {
                    myRelevantStepConfig = step; // 이 Feature가 처리해야 할 스텝을 찾음
                    break;
                }
            }
        }

        if (myRelevantStepConfig == null) {
            // 현재 HttpSecurity 설정(즉, 현재 처리 중인 AuthenticationFlowConfig)에는
            // 이 Feature가 관여할 스텝이 없음.
            log.trace("Feature {} is not relevant for any step in the current flow's steps list. Skipping specific configuration for this HttpSecurity instance.", getId());
            return;
        }

        AuthenticationFlowConfig currentFlow = http.getSharedObject(AuthenticationFlowConfig.class);
        log.debug("Applying feature {} for its relevant step: {} in flow {}",
                getId(), myRelevantStepConfig.getType(), (currentFlow != null ? currentFlow.getTypeName() : "Single/Unknown"));

        O options = (O) myRelevantStepConfig.getOptions().get("_options");
        if (options == null) {
            throw new IllegalStateException(String.format("Options not found in AuthenticationStepConfig for type '%s'.", getId()));
        }

        PlatformContext platformContext = http.getSharedObject(PlatformContext.class);
        Assert.state(platformContext != null, "PlatformContext not found in HttpSecurity shared objects.");
        ApplicationContext appContext = platformContext.applicationContext();

        // 핸들러 결정 로직 (이전 답변과 동일하게 유지 또는 개선)
        AuthenticationSuccessHandler successHandler = resolveSuccessHandler(options, currentFlow, myRelevantStepConfig, allStepsInCurrentFlow, appContext);
        AuthenticationFailureHandler failureHandler = resolveFailureHandler(options, currentFlow, myRelevantStepConfig, allStepsInCurrentFlow, appContext);

        // 실제 HttpSecurity 설정 적용
        if (this instanceof OttAuthenticationFeature) { // 현재 인스턴스가 OttAuthenticationFeature 인지 확인
            if (!(successHandler instanceof OneTimeTokenGenerationSuccessHandler)) {
                log.warn("SuccessHandler for OTT feature ({}) is not an instance of OneTimeTokenGenerationSuccessHandler. Defaulting or check config.", successHandler != null ? successHandler.getClass().getName() : "null");
                OneTimeTokenGenerationSuccessHandler ottDefaultHandler = determineDefaultOttSuccessHandler(options, currentFlow, myRelevantStepConfig, allStepsInCurrentFlow, appContext);
                // configureHttpSecurityForOtt는 OttAuthenticationFeature 에서 오버라이드 되어야 함
                ((OttAuthenticationFeature)this).configureHttpSecurityForOtt(http, (OttOptions)options, ottDefaultHandler, failureHandler);
            } else {
                ((OttAuthenticationFeature)this).configureHttpSecurityForOtt(http, (OttOptions)options, (OneTimeTokenGenerationSuccessHandler) successHandler, failureHandler);
            }
        } else {
            configureHttpSecurity(http, options, successHandler, failureHandler);
        }

        List<SafeHttpCustomizer<HttpSecurity>> rawHttpCustomizers = options.getRawHttpCustomizers();
        if (rawHttpCustomizers != null) {
            for (SafeHttpCustomizer<HttpSecurity> customizer : rawHttpCustomizers) {
                Objects.requireNonNull(customizer, "rawHttp customizer must not be null").customize(http);
            }
        }
        log.info("Feature {} applied its specific configuration for step type '{}' in flow '{}'.",
                getId(), myRelevantStepConfig.getType(), (currentFlow != null ? currentFlow.getTypeName() : "Single/Unknown"));
    }

    protected AuthenticationSuccessHandler resolveSuccessHandler(O options, AuthenticationFlowConfig currentFlow, AuthenticationStepConfig myStepConfig, List<AuthenticationStepConfig> allSteps, ApplicationContext appContext) {
        if (options.getSuccessHandler() != null) {
            return options.getSuccessHandler();
        }
        if (currentFlow != null && "mfa".equalsIgnoreCase(currentFlow.getTypeName())) {
            int currentStepIndex = allSteps.indexOf(myStepConfig);
            boolean isLastStepInMfaFlow = (currentStepIndex == allSteps.size() - 1);

            if (currentStepIndex == 0) { // MFA의 1차 인증
                return appContext.getBean(MfaCapableRestSuccessHandler.class); // 또는 Form 용 핸들러를 Bean으로 등록하고 가져오기
            } else if (isLastStepInMfaFlow) { // MFA의 마지막 Factor
                return currentFlow.getFinalSuccessHandler() != null ? currentFlow.getFinalSuccessHandler() : appContext.getBean(MfaStepBasedSuccessHandler.class);
            } else { // MFA의 중간 Factor
                return appContext.getBean(MfaStepBasedSuccessHandler.class);
            }
        }
        // 단일 인증 플로우 또는 currentFlow 정보가 없을 때
        return determineDefaultSuccessHandler(options, currentFlow, myStepConfig, allSteps, appContext);
    }

    protected AuthenticationFailureHandler resolveFailureHandler(O options, AuthenticationFlowConfig currentFlow, AuthenticationStepConfig myStepConfig, List<AuthenticationStepConfig> allSteps, ApplicationContext appContext) {
        if (options.getFailureHandler() != null) {
            return options.getFailureHandler();
        }
        if (currentFlow != null && "mfa".equalsIgnoreCase(currentFlow.getTypeName())) {
            // MfaDslConfigurer 에서 설정한 MfaFailureHandler를 가져와야 함
            // AuthenticationFlowConfig에 저장된 MfaFailureHandler는 io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler 타입
            // 이를 Spring Security의 AuthenticationFailureHandler 타입으로 변환하거나,
            // MfaAuthenticationFailureHandler가 두 인터페이스를 모두 구현하도록 함 (이전 답변에서 수정)
            if (currentFlow.getMfaFailureHandler() instanceof AuthenticationFailureHandler) {
                return (AuthenticationFailureHandler) currentFlow.getMfaFailureHandler();
            } else if (currentFlow.getMfaFailureHandler() != null) {
                log.warn("MFA flow failure handler is not an instance of Spring Security AuthenticationFailureHandler. Using default.");
                // 이 경우, MfaAuthenticationFailureHandler와 같은 Bean을 여기서 가져와야 함.
                return appContext.getBean(io.springsecurity.springsecurity6x.security.handler.MfaAuthenticationFailureHandler.class);
            }
        }
        return createDefaultFailureHandler(options, appContext);
    }

    protected AuthenticationSuccessHandler determineDefaultSuccessHandler(O options, AuthenticationFlowConfig currentFlow, AuthenticationStepConfig myStepConfig, List<AuthenticationStepConfig> allSteps, ApplicationContext appContext) {
        try {
            return appContext.getBean("jwtEmittingAndMfaAwareSuccessHandler", AuthenticationSuccessHandler.class);
        } catch (Exception e) {
            log.warn("Default success handler bean 'jwtEmittingAndMfaAwareSuccessHandler' not found for feature {}. Returning basic redirect to /.", getId(), e);
            return (request, response, authentication) -> response.sendRedirect("/");
        }
    }

    protected OneTimeTokenGenerationSuccessHandler determineDefaultOttSuccessHandler(O options, AuthenticationFlowConfig currentFlow, AuthenticationStepConfig myStepConfig, List<AuthenticationStepConfig> allSteps, ApplicationContext appContext) {
        if (currentFlow != null && "mfa".equalsIgnoreCase(currentFlow.getTypeName())) {
            // MfaStepBasedSuccessHandler가 OneTimeTokenGenerationSuccessHandler를 구현한다고 가정
            // 또는 OttAuthenticationFeature의 successHandler는 MfaDslConfigurer에서 직접 설정된 것을 사용하도록 유도
            return appContext.getBean(MfaStepBasedSuccessHandler.class);
        } else {
            try {
                return appContext.getBean("jwtEmittingAndMfaAwareSuccessHandler", OneTimeTokenGenerationSuccessHandler.class);
            } catch (Exception e) {
                log.warn("Default OTT success handler bean 'jwtEmittingAndMfaAwareSuccessHandler' not found for feature {}. Returning basic redirect to /.", getId(), e);
                return (request, response, token) -> response.sendRedirect("/");
            }
        }
    }

    protected AuthenticationFailureHandler createDefaultFailureHandler(O options, ApplicationContext appContext) {
        if (options instanceof RestOptions) {
            final ObjectMapper objectMapper = appContext.getBean(ObjectMapper.class);
            return (request, response, exception) -> {
                log.warn("Default REST authentication failure for feature {}: {}", getId(), exception.getMessage());
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                objectMapper.writeValue(response.getWriter(),
                        Map.of("error", "AUTHENTICATION_FAILED",
                                "message", exception.getMessage() != null ? exception.getMessage() : "Invalid credentials.",
                                "path", request.getRequestURI()));
            };
        } else {
            String failureUrl = determineDefaultFailureUrl(options); // 각 Feature가 기본 실패 URL 제공
            log.debug("Using default failure URL: {} for feature {}", failureUrl, getId());
            return new SimpleUrlAuthenticationFailureHandler(failureUrl);
        }
    }

    protected String determineDefaultFailureUrl(O options) {
        if (options instanceof FormOptions && ((FormOptions) options).getFailureUrl() != null) {
            return ((FormOptions) options).getFailureUrl();
        }
        // 기타 다른 AuthenticationProcessingOptions의 하위 클래스에 대한 처리 추가 가능
        return "/login?error&feature=" + getId(); // 일반적인 기본 실패 URL
    }
}
