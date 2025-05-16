package io.springsecurity.springsecurity6x.security.core.feature.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.handler.CustomTokenIssuingSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.OneTimeRedirectSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.SimpleRedirectSuccessHandler;
import jakarta.servlet.http.HttpServletResponse;
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

    @Override
    public abstract String getId();

    @Override
    public abstract int getOrder();

    protected abstract void configureHttpSecurity(HttpSecurity http, O options,
                                                  AuthenticationSuccessHandler successHandler,
                                                  AuthenticationFailureHandler failureHandler) throws Exception;

    /**
     * OTT와 같이 AuthenticationSuccessHandler가 아닌 다른 타입의 성공 핸들러를 사용하는 경우를 위해 오버로딩합니다.
     * 필요한 하위 클래스(OttAuthenticationFeature)에서 오버라이드해야 합니다.
     */
    protected void configureHttpSecurity(HttpSecurity http, O options,
                                         OneTimeTokenGenerationSuccessHandler oneTimeTokenGenerationSuccessHandler,
                                         AuthenticationFailureHandler failureHandler) throws Exception {
        // 이 메소드가 호출된다는 것은 하위 클래스가 이 버전을 오버라이드하지 않았음을 의미하며,
        // 이는 해당 AuthenticationFeature가 OneTimeTokenGenerationSuccessHandler를 지원하지 않거나
        // 잘못된 configureHttpSecurity 메소드가 호출되었음을 나타낼 수 있습니다.
        // 보다 명확한 오류를 위해 예외를 발생시키거나 로깅을 추가할 수 있습니다.
        throw new UnsupportedOperationException(
                String.format("Feature %s does not support OneTimeTokenGenerationSuccessHandler directly. " +
                        "Ensure the correct configureHttpSecurity method is overridden and called.", getId())
        );
    }


    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> steps, StateConfig state) throws Exception {
        if (steps == null || steps.isEmpty()) {
            return;
        }

        AuthenticationStepConfig myStep = steps.stream()
                .filter(s -> getId().equalsIgnoreCase(s.getType()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        String.format("Step config missing for %s type in %s.", getId(), this.getClass().getSimpleName())));

        O options = (O) myStep.getOptions().get("_options");
        if (options == null) {
            throw new IllegalStateException(
                    String.format("Options not found in AuthenticationStepConfig for %s type.", getId()));
        }

        int currentStepIndex = steps.indexOf(myStep);
        boolean isLastStep = currentStepIndex == steps.size() - 1;

        PlatformContext platformContext = http.getSharedObject(PlatformContext.class);
        Assert.state(platformContext != null, "PlatformContext not found in HttpSecurity shared objects.");
        ApplicationContext appContext = platformContext.applicationContext();

        // --- 성공 핸들러 결정 ---
        AuthenticationSuccessHandler successHandlerForAuth = null;
        OneTimeTokenGenerationSuccessHandler successHandlerForOtt = null;

        if (isLastStep) {
            CustomTokenIssuingSuccessHandler tokenIssuingHandler = appContext.getBean(CustomTokenIssuingSuccessHandler.class);
            successHandlerForAuth = tokenIssuingHandler;
            if (AuthType.OTT.name().equalsIgnoreCase(getId())) {
                successHandlerForOtt = tokenIssuingHandler;
            }
        } else {
            Assert.state(currentStepIndex + 1 < steps.size(),
                    "MFA flow configuration error: No next step defined after current step " + currentStepIndex + " for feature " + getId());

            AuthenticationStepConfig nextStep = steps.get(currentStepIndex + 1);
            Object nextStepOptsObj = nextStep.getOptions().get("_options");
            String targetUrl = extractTargetUrlFromOptions(nextStepOptsObj, nextStep.getType());

            if (AuthType.OTT.name().equalsIgnoreCase(getId())) {
                successHandlerForOtt = new OneTimeRedirectSuccessHandler(targetUrl);
            } else {
                successHandlerForAuth = new SimpleRedirectSuccessHandler(targetUrl);
            }
        }

        if (options.getSuccessHandler() != null) {
            if (AuthType.OTT.name().equalsIgnoreCase(getId()) && options.getSuccessHandler() instanceof OneTimeTokenGenerationSuccessHandler) {
                successHandlerForOtt = (OneTimeTokenGenerationSuccessHandler) options.getSuccessHandler();

            } else if (!AuthType.OTT.name().equalsIgnoreCase(getId()) && options.getSuccessHandler() != null) {
                successHandlerForAuth = options.getSuccessHandler();

            } else if (options.getSuccessHandler() != null) {
                // 타입 불일치 경고 또는 예외 처리
                System.err.printf("Warning: DSL configured successHandler type mismatch for feature %s. Expected %s, got %s.%n",
                        getId(),
                        AuthType.OTT.name().equalsIgnoreCase(getId()) ? OneTimeTokenGenerationSuccessHandler.class.getSimpleName() : AuthenticationSuccessHandler.class.getSimpleName(),
                        options.getSuccessHandler().getClass().getSimpleName());
                // 기본적으로 isLastStep에 따라 결정된 핸들러를 그대로 사용하거나, 에러를 발생시킬 수 있습니다.
                // 여기서는 isLastStep 기반으로 결정된 핸들러를 유지합니다.
            }
        }


        // --- 실패 핸들러 결정 ---
        AuthenticationFailureHandler failureHandler = options.getFailureHandler();
        if (failureHandler == null) {
            if (AuthType.REST.name().equalsIgnoreCase(getId())) {
                final ObjectMapper objectMapper = appContext.getBean(ObjectMapper.class);
                failureHandler = (request, response, exception) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    objectMapper.writeValue(response.getWriter(),
                            Map.of("error", "Authentication Failed", "message", exception.getMessage()));
                };
            } else {
                String defaultFailureUrl = determineDefaultFailureUrl(options);
                failureHandler = new SimpleUrlAuthenticationFailureHandler(defaultFailureUrl);
            }
        }

        // --- HttpSecurity 설정 위임 ---
        if (AuthType.OTT.name().equalsIgnoreCase(getId())) {
            Assert.notNull(successHandlerForOtt, "successHandlerForOtt cannot be null for OttAuthenticationFeature");
            configureHttpSecurity(http, options, successHandlerForOtt, failureHandler);
        } else {
            Assert.notNull(successHandlerForAuth, "successHandlerForAuth cannot be null for " + getId() + " feature");
            configureHttpSecurity(http, options, successHandlerForAuth, failureHandler);
        }

        // --- 공통 후처리 (예: Raw HttpSecurity Customizers 적용) ---
        List<SafeHttpCustomizer<HttpSecurity>> rawHttpCustomizers = options.getRawHttpCustomizers();
        if (rawHttpCustomizers != null) {
            for (SafeHttpCustomizer<HttpSecurity> customizer : rawHttpCustomizers) {
                Objects.requireNonNull(customizer, "rawHttp customizer must not be null").customize(http);
            }
        }
    }

    protected String extractTargetUrlFromOptions(Object optionsObject, String stepType) {
        // if (optionsObject instanceof AuthenticationProcessingOptions) {
        // }
        if (AuthType.OTT.name().equalsIgnoreCase(stepType)) {
            return "/mfa/verify/ott";
        } else if (AuthType.PASSKEY.name().equalsIgnoreCase(stepType)) {
            return "/mfa/verify/passkey";
        }
        return "/mfa/select-factor";
    }

    protected String determineDefaultFailureUrl(O options) {
        if (options instanceof FormOptions) {
            return ((FormOptions) options).getFailureUrl() != null ? ((FormOptions) options).getFailureUrl() : "/loginForm?error=" + getId();
        } else if (options instanceof OttOptions) {
            // OttOptions에 failureUrl 같은 필드가 있다면 사용
            return "/loginOtt?error=" + getId();
        } else if (options instanceof PasskeyOptions) {
            // PasskeyOptions에 failureUrl 같은 필드가 있다면 사용
            return "/loginPasskey?error=" + getId();
        }
        // REST는 이 메소드를 직접 호출하지 않음 (apply에서 별도 처리)
        return "/login?error=" + getId();
    }
}
