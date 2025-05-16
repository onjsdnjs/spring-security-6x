package io.springsecurity.springsecurity6x.security.core.feature.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.*;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.handler.CustomTokenIssuingSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.OneTimeRedirectSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.SimpleRedirectSuccessHandler;
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

    /**
     * 각 하위 클래스에서 해당 인증 방식에 특화된 HttpSecurity 설정을 적용합니다.
     * 이 메소드는 일반적인 AuthenticationSuccessHandler를 사용합니다.
     */
    protected abstract void configureHttpSecurity(HttpSecurity http, O options,
                                                  AuthenticationSuccessHandler successHandler,
                                                  AuthenticationFailureHandler failureHandler) throws Exception;

    /**
     * OTT와 같이 OneTimeTokenGenerationSuccessHandler를 사용하는 경우를 위해 오버로딩합니다.
     * OttAuthenticationFeature 에서 이 메소드를 오버라이드하여 사용합니다.
     */
    protected void configureHttpSecurityForOtt(HttpSecurity http, O options,
                                               OneTimeTokenGenerationSuccessHandler ottSuccessHandler,
                                               AuthenticationFailureHandler failureHandler) throws Exception {
        throw new UnsupportedOperationException(
                String.format("Feature %s does not support OneTimeTokenGenerationSuccessHandler. " +
                        "Override configureHttpSecurityForOtt in the subclass if needed.", getId())
        );
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> steps, StateConfig state) throws Exception {
        if (steps == null || steps.isEmpty()) {
            log.debug("No steps provided for feature {}, skipping apply.", getId());
            return;
        }

        AuthenticationStepConfig myStep = steps.stream()
                .filter(s -> getId().equalsIgnoreCase(s.getType()))
                .findFirst()
                .orElse(null); // 찾지 못하면 null 반환

        if (myStep == null) {
            // 이 Feature에 해당하는 스텝이 현재 Flow에 없으면 아무것도 하지 않음.
            // 이는 정상적인 상황일 수 있음 (예: MFA Flow 에서 특정 Factor만 사용하는 경우)
            log.trace("No step config found for feature {} in the current flow, skipping apply.", getId());
            return;
        }

        O options = (O) myStep.getOptions().get("_options");
        if (options == null) {
            throw new IllegalStateException(
                    String.format("Options not found in AuthenticationStepConfig for %s type (Feature: %s).", getId(), this.getClass().getSimpleName()));
        }

        int currentStepIndex = steps.indexOf(myStep);
        boolean isLastStep = currentStepIndex == steps.size() - 1;

        PlatformContext platformContext = http.getSharedObject(PlatformContext.class);
        Assert.state(platformContext != null, "PlatformContext not found in HttpSecurity shared objects.");
        ApplicationContext appContext = platformContext.applicationContext();

        // --- 성공 핸들러 결정 ---
        AuthenticationSuccessHandler successHandlerForAuth = null;
        OneTimeTokenGenerationSuccessHandler successHandlerForOtt = null;

        AuthenticationSuccessHandler dslConfiguredSuccessHandler = options.getSuccessHandler();

        if (isLastStep) {
            CustomTokenIssuingSuccessHandler tokenIssuingHandler = appContext.getBean(CustomTokenIssuingSuccessHandler.class);
            successHandlerForAuth = tokenIssuingHandler;
            if (AuthType.OTT.name().equalsIgnoreCase(getId())) {
                successHandlerForOtt = tokenIssuingHandler; // CustomTokenIssuingSuccessHandler가 OneTimeTokenGenerationSuccessHandler도 구현
            }
        } else {
            Assert.state(currentStepIndex + 1 < steps.size(),
                    String.format("MFA flow configuration error: No next step defined after current step %d for feature %s", currentStepIndex, getId()));
            AuthenticationStepConfig nextStep = steps.get(currentStepIndex + 1);
            Object nextStepOptsObj = nextStep.getOptions().get("_options");
            String targetUrl = extractTargetUrlFromOptions(nextStepOptsObj, nextStep.getType(), options);

            if (AuthType.OTT.name().equalsIgnoreCase(getId())) {
                // OTT는 토큰 생성 성공 핸들러가 다음 단계로 안내 (실제 로그인 성공 핸들러는 아님)
                // 따라서 isLastStep이 false인 OTT는 항상 OneTimeRedirectSuccessHandler를 사용
                successHandlerForOtt = new OneTimeRedirectSuccessHandler(targetUrl);
            } else {
                successHandlerForAuth = new SimpleRedirectSuccessHandler(targetUrl);
            }
        }

        // 사용자가 DSL을 통해 successHandler를 명시적으로 설정한 경우, 그 설정을 우선 적용
        if (dslConfiguredSuccessHandler != null) {
            if (AuthType.OTT.name().equalsIgnoreCase(getId())) {
                if (dslConfiguredSuccessHandler instanceof OneTimeTokenGenerationSuccessHandler) {
                    successHandlerForOtt = (OneTimeTokenGenerationSuccessHandler) dslConfiguredSuccessHandler;
                    log.debug("Using DSL configured OneTimeTokenGenerationSuccessHandler for OTT feature: {}", dslConfiguredSuccessHandler.getClass().getName());
                } else {
                    log.warn("DSL configured successHandler for OTT feature is not of type OneTimeTokenGenerationSuccessHandler. Type: {}. Using default/step-based handler instead.",
                            dslConfiguredSuccessHandler.getClass().getName());
                }
            } else {
                successHandlerForAuth = dslConfiguredSuccessHandler;
                log.debug("Using DSL configured AuthenticationSuccessHandler for {} feature: {}", getId(), dslConfiguredSuccessHandler.getClass().getName());
            }
        }


        // --- 실패 핸들러 결정 ---
        AuthenticationFailureHandler failureHandler = options.getFailureHandler();
        if (failureHandler == null) {
            failureHandler = createDefaultFailureHandler(options, appContext);
        }

        // --- HttpSecurity 설정 위임 ---
        log.debug("Configuring HttpSecurity for feature: {}, isLastStep: {}", getId(), isLastStep);
        if (AuthType.OTT.name().equalsIgnoreCase(getId())) {
            Assert.notNull(successHandlerForOtt, "successHandlerForOtt cannot be null for OttAuthenticationFeature");
            configureHttpSecurityForOtt(http, options, successHandlerForOtt, failureHandler);
        } else {
            Assert.notNull(successHandlerForAuth, "successHandlerForAuth cannot be null for " + getId() + " feature");
            configureHttpSecurity(http, options, successHandlerForAuth, failureHandler);
        }

        // --- 공통 후처리 (Raw HttpSecurity Customizers 적용) ---
        List<SafeHttpCustomizer<HttpSecurity>> rawHttpCustomizers = options.getRawHttpCustomizers();
        if (rawHttpCustomizers != null) {
            log.debug("Applying {} raw HttpSecurity customizers for feature: {}", rawHttpCustomizers.size(), getId());
            for (SafeHttpCustomizer<HttpSecurity> customizer : rawHttpCustomizers) {
                Objects.requireNonNull(customizer, "rawHttp customizer must not be null").customize(http);
            }
        }
        log.info("Successfully applied configurations for AuthenticationFeature: {}", getId());
    }

    protected String extractTargetUrlFromOptions(Object nextStepOptionsObject, String nextStepType, O currentAuthOptions) {
        // 1. 다음 스텝 옵션에서 URL을 가져오려는 시도 (가상의 메소드)
        // if (nextStepOptionsObject instanceof AuthenticationProcessingOptions) {
        //     String nextUrl = ((AuthenticationProcessingOptions) nextStepOptionsObject).getExplicitNextStepUrl();
        //     if (nextUrl != null) return nextUrl;
        // }

        // 2. 현재 인증 방식 옵션에서 다음 MFA 선택 페이지 URL을 가져오려는 시도
        // if (currentAuthOptions instanceof FormOptions && ((FormOptions) currentAuthOptions).getMfaTransitionUrl() != null) {
        //    return ((FormOptions) currentAuthOptions).getMfaTransitionUrl();
        // }
        // ... 다른 옵션 타입에 대해서도 유사하게 ...

        // 3. 다음 스텝의 타입에 따라 기본 URL 반환 (가장 기본적인 fallback)
        log.debug("Extracting target URL for next step type: {}", nextStepType);
        if (AuthType.OTT.name().equalsIgnoreCase(nextStepType)) {
            return "/mfa/verify/ott";
        } else if (AuthType.PASSKEY.name().equalsIgnoreCase(nextStepType)) {
            return "/mfa/verify/passkey";
        }
        // 기본적으로는 다음 Factor 선택 페이지로 이동
        return "/mfa/select-factor";
    }

    protected AuthenticationFailureHandler createDefaultFailureHandler(O options, ApplicationContext appContext) {
        if (options instanceof RestOptions) {
            final ObjectMapper objectMapper = appContext.getBean(ObjectMapper.class);
            return (request, response, exception) -> {
                log.warn("Default REST authentication failure: {}", exception.getMessage());
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                objectMapper.writeValue(response.getWriter(),
                        Map.of("error", "AUTHENTICATION_FAILED",
                                "message", exception.getMessage() != null ? exception.getMessage() : "Invalid credentials or authentication error.",
                                "path", request.getRequestURI()));
            };
        } else {
            String failureUrl = determineDefaultFailureUrl(options);
            log.debug("Using default failure URL: {} for feature {}", failureUrl, getId());
            return new SimpleUrlAuthenticationFailureHandler(failureUrl);
        }
    }

    protected String determineDefaultFailureUrl(O options) {
        String featureSpecificErrorUrl = "/login?error_feature=" + getId();
        if (options instanceof FormOptions && ((FormOptions) options).getFailureUrl() != null) {
            return ((FormOptions) options).getFailureUrl();
        } else if (options instanceof OttOptions) {
            // OttOptions에 getFailureUrl()이 있다면 사용, 없으면 기본값
            // return ((OttOptions) options).getFailureUrl() != null ? ((OttOptions) options).getFailureUrl() : "/loginOtt?error";
            return "/loginOtt?error_ott_default_in_abstract";
        } else if (options instanceof PasskeyOptions) {
            // PasskeyOptions에 getFailureUrl()이 있다면 사용, 없으면 기본값
            return "/loginPasskey?error_passkey_default_in_abstract";
        }
        // REST는 createDefaultFailureHandler에서 별도 처리
        return featureSpecificErrorUrl;
    }
}
