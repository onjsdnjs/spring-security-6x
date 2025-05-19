package io.springsecurity.springsecurity6x.security.core.feature.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.handler.MfaAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaCapableRestSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaStepBasedSuccessHandler;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@Slf4j
public abstract class AbstractAuthenticationFeature<O extends AuthenticationProcessingOptions> implements AuthenticationFeature {

    /**
     * 각 인증 방식에 특화된 HttpSecurity 설정을 적용합니다.
     * OttAuthenticationFeature는 이 메소드 대신 configureHttpSecurityForOtt를 사용합니다.
     *
     * @param http HttpSecurity 객체
     * @param options 해당 인증 방식의 옵션 객체
     * @param successHandler 적용할 성공 핸들러
     * @param failureHandler 적용할 실패 핸들러
     * @throws Exception 설정 중 발생 가능한 예외
     */
    protected abstract void configureHttpSecurity(HttpSecurity http, O options,
                                                  AuthenticationSuccessHandler successHandler,
                                                  AuthenticationFailureHandler failureHandler) throws Exception;

    /**
     * OTT 인증 방식에 특화된 HttpSecurity 설정을 적용합니다.
     * OttAuthenticationFeature 에서 오버라이드하여 사용합니다.
     *
     * @param http HttpSecurity 객체
     * @param options OttOptions 객체 (타입 구체화)
     * @param ottSuccessHandler 적용할 OTT 생성 성공 핸들러
     * @param failureHandler 적용할 실패 핸들러
     * @throws Exception 설정 중 발생 가능한 예외
     */
    protected void configureHttpSecurityForOtt(HttpSecurity http, OttOptions options, // O 대신 OttOptions
                                               OneTimeTokenGenerationSuccessHandler ottSuccessHandler,
                                               AuthenticationFailureHandler failureHandler) throws Exception {
        // 기본 구현은 지원하지 않음을 명시하거나, OttAuthenticationFeature 에서 반드시 오버라이드하도록 함
        if (!(this instanceof OttAuthenticationFeature)) {
            throw new UnsupportedOperationException(
                    String.format("Feature %s is not an OTT feature and should not call configureHttpSecurityForOtt. " +
                            "This method must be overridden by OttAuthenticationFeature.", getId())
            );
        }
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> allStepsInCurrentFlow, StateConfig stateConfig) throws Exception {
        Objects.requireNonNull(http, "HttpSecurity cannot be null");

        AuthenticationStepConfig myRelevantStepConfig = null;
        if (!CollectionUtils.isEmpty(allStepsInCurrentFlow)) {
            for (AuthenticationStepConfig step : allStepsInCurrentFlow) {
                if (getId().equalsIgnoreCase(step.getType())) {
                    myRelevantStepConfig = step; // 이 Feature가 처리해야 할 스텝을 찾음
                    break;
                }
            }
        }

        // 단일 인증 흐름(MFA가 아닌 경우)에서는 allStepsInCurrentFlow가 비어있거나,
        // 현재 Feature와 직접 매칭되는 StepConfig가 없을 수 있음.
        // 이 경우, HttpSecurity에 직접 공유된 Options 객체가 있는지 확인 (플랫폼 설계에 따라 달라짐)
        // 여기서는 myRelevantStepConfig가 null 이면 이 Feature는 현재 Flow에 적용되지 않는 것으로 간주.
        if (myRelevantStepConfig == null) {
            log.trace("AuthenticationFeature [{}]: No relevant AuthenticationStepConfig found in the current flow's steps. Skipping specific configuration for this HttpSecurity instance.", getId());
            return;
        }

        AuthenticationFlowConfig currentFlow = http.getSharedObject(AuthenticationFlowConfig.class); // 현재 적용 중인 FlowConfig
        log.debug("AuthenticationFeature [{}]: Applying for its relevant step: {} in flow: {}",
                getId(), myRelevantStepConfig.getType(), (currentFlow != null ? currentFlow.getTypeName() : "Single/Unknown"));

        O options = (O) myRelevantStepConfig.getOptions().get("_options");
        if (options == null) {
            throw new IllegalStateException(
                    String.format("AuthenticationFeature [%s]: Options not found in AuthenticationStepConfig for type '%s'. " +
                            "Ensure XxxDslConfigurerImpl correctly builds and stores options.", getId(), getId())
            );
        }

        PlatformContext platformContext = http.getSharedObject(PlatformContext.class);
        Assert.state(platformContext != null, "PlatformContext not found in HttpSecurity shared objects. It must be set by the orchestrator.");
        ApplicationContext appContext = platformContext.applicationContext();
        Objects.requireNonNull(appContext, "ApplicationContext from PlatformContext cannot be null");

        AuthenticationSuccessHandler successHandler = resolveSuccessHandler(options, currentFlow, myRelevantStepConfig, allStepsInCurrentFlow, appContext);
        AuthenticationFailureHandler failureHandler = resolveFailureHandler(options, currentFlow, myRelevantStepConfig, allStepsInCurrentFlow, appContext);

        if (this instanceof OttAuthenticationFeature ottFeature) { // Java 16+ 패턴 변수
            OneTimeTokenGenerationSuccessHandler resolvedOttSuccessHandler = null;
            if (!(successHandler instanceof OneTimeTokenGenerationSuccessHandler)) {
                log.warn("AuthenticationFeature [{}]: Resolved successHandler for OTT feature is not an instance of OneTimeTokenGenerationSuccessHandler (Actual: {}). " +
                                "Attempting to use a default OTT success handler.",
                        getId(), (successHandler != null ? successHandler.getClass().getName() : "null"));
                resolvedOttSuccessHandler = determineDefaultOttSuccessHandler(options, currentFlow, myRelevantStepConfig, allStepsInCurrentFlow, appContext);
                if (resolvedOttSuccessHandler == null) {
                    throw new IllegalStateException("Unable to determine a valid OneTimeTokenGenerationSuccessHandler for OTT feature " + getId());
                }
            }
            ottFeature.configureHttpSecurityForOtt(http, (OttOptions)options, resolvedOttSuccessHandler, failureHandler);
        } else {
            configureHttpSecurity(http, options, successHandler, failureHandler);
        }

        options.applyCommonSecurityConfigs(http); // AbstractOptions에 추가된 헬퍼 메소드 호출

        log.info("AuthenticationFeature [{}]: Applied its specific configuration for step type '{}' in flow '{}'.",
                getId(), myRelevantStepConfig.getType(), (currentFlow != null ? currentFlow.getTypeName() : "Single/Unknown"));
    }

    protected AuthenticationSuccessHandler resolveSuccessHandler(
            O options, @Nullable AuthenticationFlowConfig currentFlow,
            AuthenticationStepConfig myStepConfig, @Nullable List<AuthenticationStepConfig> allSteps,
            ApplicationContext appContext) {
        // 1. Options에 명시적으로 설정된 핸들러 사용
        if (options.getSuccessHandler() != null) {
            log.debug("AuthenticationFeature [{}]: Using successHandler from options: {}", getId(), options.getSuccessHandler().getClass().getSimpleName());
            return options.getSuccessHandler();
        }

        // 2. MFA 흐름인 경우의 핸들러 결정
        if (currentFlow != null && "mfa".equalsIgnoreCase(currentFlow.getTypeName()) && allSteps != null) {
            int currentStepIndex = allSteps.indexOf(myStepConfig);
            boolean isFirstStepInMfaFlow = (currentStepIndex == 0); // MFA의 1차 인증 단계
            boolean isLastStepInMfaFlow = (currentStepIndex == allSteps.size() - 1); // MFA의 마지막 Factor 단계

            if (isFirstStepInMfaFlow) {
                // MFA의 1차 인증 성공 시: MfaCapableRestSuccessHandler (REST) 또는 유사한 Form용 핸들러
                // (MfaCapableRestSuccessHandler가 JWT 발급 및 MFA 시작을 담당한다고 가정)
                log.debug("AuthenticationFeature [{}]: Resolving successHandler for MFA primary step.", getId());
                return appContext.getBean(MfaCapableRestSuccessHandler.class); // 플랫폼에 정의된 빈 이름 사용
            } else if (isLastStepInMfaFlow) {
                // MFA의 마지막 Factor 성공 시: currentFlow에 정의된 finalSuccessHandler 또는 MfaStepBasedSuccessHandler
                log.debug("AuthenticationFeature [{}]: Resolving successHandler for MFA final factor step.", getId());
                return Optional.ofNullable(currentFlow.getFinalSuccessHandler())
                        .orElseGet(() -> appContext.getBean(MfaStepBasedSuccessHandler.class)); // 플랫폼에 정의된 빈 이름
            } else {
                // MFA의 중간 Factor 성공 시: MfaStepBasedSuccessHandler (다음 MFA 단계로 진행)
                log.debug("AuthenticationFeature [{}]: Resolving successHandler for MFA intermediate factor step.", getId());
                return appContext.getBean(MfaStepBasedSuccessHandler.class); // 플랫폼에 정의된 빈 이름
            }
        }

        // 3. 단일 인증 흐름 또는 위 조건에 해당하지 않는 경우의 기본 핸들러
        log.debug("AuthenticationFeature [{}]: Resolving default successHandler.", getId());
        return determineDefaultSuccessHandler(options, currentFlow, myStepConfig, allSteps, appContext);
    }

    protected AuthenticationFailureHandler resolveFailureHandler(
            O options, @Nullable AuthenticationFlowConfig currentFlow,
            AuthenticationStepConfig myStepConfig, @Nullable List<AuthenticationStepConfig> allSteps,
            ApplicationContext appContext) {
        // 1. Options에 명시적으로 설정된 핸들러 사용
        if (options.getFailureHandler() != null) {
            log.debug("AuthenticationFeature [{}]: Using failureHandler from options: {}", getId(), options.getFailureHandler().getClass().getSimpleName());
            return options.getFailureHandler();
        }

        // 2. MFA 흐름인 경우의 핸들러 결정
        if (currentFlow != null && "mfa".equalsIgnoreCase(currentFlow.getTypeName())) {
            // MfaDslConfigurer 에서 설정한 MfaFailureHandler 사용
            Object mfaSpecificFailureHandler = currentFlow.getMfaFailureHandler(); // 플랫폼의 MfaFailureHandler 타입
            if (mfaSpecificFailureHandler instanceof AuthenticationFailureHandler springSecurityFailureHandler) {
                log.debug("AuthenticationFeature [{}]: Using MfaFailureHandler from current MFA flow config.", getId());
                return springSecurityFailureHandler;
            } else if (mfaSpecificFailureHandler != null) {
                log.warn("AuthenticationFeature [{}]: MfaFailureHandler in MFA flow config is not an instance of Spring Security AuthenticationFailureHandler. Type: {}. Using platform default.",
                        getId(), mfaSpecificFailureHandler.getClass().getName());
                // 플랫폼의 MfaAuthenticationFailureHandler 빈을 가져와 사용
                return appContext.getBean(MfaAuthenticationFailureHandler.class);
            }
        }

        // 3. 단일 인증 흐름 또는 위 조건에 해당하지 않는 경우의 기본 핸들러
        log.debug("AuthenticationFeature [{}]: Resolving default failureHandler.", getId());
        return createDefaultFailureHandler(options, appContext);
    }

    /**
     * 각 Feature가 구현하여 자신의 기본 성공 핸들러를 결정합니다.
     */
    protected AuthenticationSuccessHandler determineDefaultSuccessHandler(
            O options, @Nullable AuthenticationFlowConfig currentFlow,
            AuthenticationStepConfig myStepConfig, @Nullable List<AuthenticationStepConfig> allSteps,
            ApplicationContext appContext) {
        // 기본적으로 JWT를 발급하는 핸들러를 사용하거나, Feature별로 다른 기본 핸들러 정의
        try {
            // 플랫폼 전역의 기본 성공 핸들러 (예: JWT 발급 + MFA 인지)
            return appContext.getBean("jwtEmittingAndMfaAwareSuccessHandler", AuthenticationSuccessHandler.class);
        } catch (Exception e) {
            log.warn("AuthenticationFeature [{}]: Default success handler bean 'jwtEmittingAndMfaAwareSuccessHandler' not found. Defaulting to simple redirect to '/'.", getId(), e);
            return (request, response, authentication) -> response.sendRedirect("/"); // 매우 기본적인 fallback
        }
    }

    /**
     * 각 Feature가 구현하여 자신의 OTT용 기본 성공 핸들러를 결정합니다. (OttAuthenticationFeature에서 오버라이드)
     */
    protected OneTimeTokenGenerationSuccessHandler determineDefaultOttSuccessHandler(
            O options, @Nullable AuthenticationFlowConfig currentFlow, // O를 OttOptions로 캐스팅 필요
            AuthenticationStepConfig myStepConfig, @Nullable List<AuthenticationStepConfig> allSteps,
            ApplicationContext appContext) {
        // 이 메소드는 OttAuthenticationFeature에서 반드시 오버라이드 되어야 함
        log.warn("AuthenticationFeature [{}]: determineDefaultOttSuccessHandler called on non-OTT feature. This indicates a logic error. Returning basic redirect handler.", getId());
        return (request, response, token) -> response.sendRedirect("/?ott_default_redirect"); // 기본 fallback
    }


    /**
     * 각 Feature가 구현하여 자신의 기본 실패 핸들러를 생성합니다.
     */
    protected AuthenticationFailureHandler createDefaultFailureHandler(O options, ApplicationContext appContext) {
        // REST 방식인 경우 JSON 오류 응답, 그 외에는 URL 리다이렉션
        if (options instanceof RestOptions) {
            final ObjectMapper objectMapper;
            try {
                objectMapper = appContext.getBean(ObjectMapper.class);
            } catch (Exception e) {
                log.error("AuthenticationFeature [{}]: ObjectMapper bean not found for creating default REST failure handler. Cannot provide JSON error response.", getId(), e);
                return (request, response, exception) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication Failed");
            }
            return (request, response, exception) -> {
                log.warn("AuthenticationFeature [{}]: Default REST authentication failure: {}", getId(), exception.getMessage());
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                try {
                    objectMapper.writeValue(response.getWriter(),
                            Map.of("timestamp", System.currentTimeMillis(),
                                    "status", HttpServletResponse.SC_UNAUTHORIZED,
                                    "error", "Unauthorized",
                                    "message", exception.getMessage() != null ? exception.getMessage() : "Invalid credentials.",
                                    "path", request.getRequestURI()));
                } catch (IOException e) {
                    log.error("AuthenticationFeature [{}]: Error writing JSON error response.", getId(), e);
                }
            };
        } else {
            String failureUrl = determineDefaultFailureUrl(options);
            log.debug("AuthenticationFeature [{}]: Using default failure URL: {} for non-REST flow.", getId(), failureUrl);
            return new SimpleUrlAuthenticationFailureHandler(failureUrl);
        }
    }

    /**
     * 각 Feature가 구현하여 자신의 기본 실패 URL을 결정합니다. (주로 Form 기반 Feature에서 오버라이드)
     */
    protected String determineDefaultFailureUrl(O options) {
        // FormOptions의 경우 failureUrl을 사용하도록 FormAuthenticationFeature에서 오버라이드
        // 일반적인 기본 실패 URL
        return "/login?error&feature_type=" + getId();
    }
}
