package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState; // 사용자의 실제 MfaState enum 경로로 수정하십시오.
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Slf4j
public class DefaultChallengeGenerator implements ChallengeGenerator {

    @Override
    public Map<String, Object> generate(FactorContext ctx) {
        Objects.requireNonNull(ctx, "FactorContext cannot be null. MFA flow might not have been initialized correctly.");

        MfaState state = ctx.getCurrentState();
        AuthType currentFactorType = ctx.getCurrentProcessingFactor();
        FactorAuthenticationOptions currentFactorOptions = ctx.getCurrentFactorOptions();

        Map<String, Object> payload = new HashMap<>();

        if (state == null) {
            log.error("[ChallengeGenerator] MFA state is null in FactorContext. Session ID: {}. Cannot generate challenge.", ctx.getMfaSessionId());
            payload.put("error", "MFA_STATE_NULL");
            payload.put("message", "MFA state is missing, cannot generate challenge.");
            return payload;
        }

        // 중요: 아래 MfaState.FACTOR_CHALLENGE_INITIATED 와 MfaState.AWAITING_MFA_FACTOR_SELECTION 은
        // 사용자의 실제 MfaState enum에 정의된 값으로 변경해야 합니다.
        if (state == MfaState.FACTOR_CHALLENGE_INITIATED) { // 예시 상태값
            if (currentFactorType == null) {
                log.error("[ChallengeGenerator] Current processing factor is not set for state: {} and session ID: {}. Cannot generate challenge.", state, ctx.getMfaSessionId());
                payload.put("error", "FACTOR_TYPE_MISSING");
                payload.put("message", "Current authentication factor type is not set.");
                return payload;
            }

            payload.put("factorType", currentFactorType.name());
            log.debug("[ChallengeGenerator] Generating challenge for factorType: {}, state: {}, session ID: {}", currentFactorType, state, ctx.getMfaSessionId());

            switch (currentFactorType) {
                case FORM:
                    FormOptions formOpts = getTypedOptions(currentFactorOptions, FormOptions.class, FormOptions.builder().build(), "FORM", ctx.getMfaSessionId());
                    payload.put("mode", "FORM_SUBMISSION_REQUIRED");
                    payload.put("loginPageUrl", formOpts.getLoginPage());
                    payload.put("processingUrl", formOpts.getLoginProcessingUrl()); // FactorAuthenticationOptions에서 상속
                    payload.put("usernameParameter", formOpts.getUsernameParameter());
                    payload.put("passwordParameter", formOpts.getPasswordParameter());
                    payload.put("fields", List.of(
                            Objects.toString(formOpts.getUsernameParameter(), "username"),
                            Objects.toString(formOpts.getPasswordParameter(), "password")
                    ));
                    break;

                case REST:
                    RestOptions restOpts = getTypedOptions(currentFactorOptions, RestOptions.class, RestOptions.builder().build(), "REST", ctx.getMfaSessionId());
                    payload.put("mode", "API_CREDENTIAL_SUBMISSION_REQUIRED");
                    payload.put("url", restOpts.getLoginProcessingUrl()); // FactorAuthenticationOptions에서 상속
                    payload.put("method", "POST");
                    payload.put("bodySchema", Map.of(
                            Objects.toString(restOpts.getUsernameParameter(), "username"), "string",
                            Objects.toString(restOpts.getPasswordParameter(), "password"), "string"
                    ));
                    break;

                case OTT:
                    OttOptions ottOpts = getTypedOptions(currentFactorOptions, OttOptions.class, OttOptions.builder().build(), "OTT", ctx.getMfaSessionId());
                    payload.put("mode", "OTT_CODE_REQUIRED");
                    payload.put("generationUrl", ottOpts.getTokenGeneratingUrl());
                    payload.put("submitUrl", ottOpts.getProcessingUrl()); // FactorAuthenticationOptions에서 상속 (코드 제출용)
                    payload.put("submitField", Objects.toString(ottOpts.getTokenParameterName(), "token"));
                    break;

                case PASSKEY:
                    PasskeyOptions passkeyOpts = getTypedOptions(currentFactorOptions, PasskeyOptions.class, null, "PASSKEY", ctx.getMfaSessionId());
                    if (passkeyOpts == null) { // PasskeyOptions는 rpId 등 필수값이 있어 기본값 생성이 어려움
                        log.error("[ChallengeGenerator] PasskeyOptions are essential and not found or invalid for PASSKEY factor. Session ID: {}", ctx.getMfaSessionId());
                        payload.put("error", "PASSKEY_OPTIONS_MISSING");
                        payload.put("message", "Passkey configuration options are missing or invalid.");
                        return payload;
                    }
                    payload.put("mode", "PASSKEY_AUTHENTICATION_REQUIRED");
                    payload.put("assertionOptionsUrl", passkeyOpts.getAssertionOptionsEndpoint()); // PasskeyOptions에 추가된 getter
                    payload.put("assertionVerificationUrl", passkeyOpts.getProcessingUrl()); // FactorAuthenticationOptions에서 상속
                    payload.put("rpId", passkeyOpts.getRpId());

                    Object webAuthnOptions = ctx.getChallengePayload("publicKeyCredentialRequestOptions");
                    if (webAuthnOptions != null) {
                        payload.put("options", webAuthnOptions);
                    } else {
                        log.warn("[ChallengeGenerator] No pre-generated WebAuthn options in FactorContext for PASSKEY. Client should fetch from assertionOptionsUrl. Session ID: {}", ctx.getMfaSessionId());
                        payload.put("options", Collections.emptyMap());
                    }
                    break;

                default:
                    log.error("[ChallengeGenerator] Unsupported factor type {} for challenge generation in state {} for session ID: {}", currentFactorType, state, ctx.getMfaSessionId());
                    payload.put("error", "UNSUPPORTED_FACTOR");
                    payload.put("message", "Challenge generation for factor type " + currentFactorType + " is not supported.");
                    return payload;
            }
        } else if (state == MfaState.AWAITING_MFA_FACTOR_SELECTION) { // 예시 상태값
            log.debug("[ChallengeGenerator] Generating payload for factor selection. Session ID: {}", ctx.getMfaSessionId());
            payload.put("mode", "FACTOR_SELECTION_REQUIRED");
//            payload.put("selectionUrl", ctx.getAttributeOrDefault("mfaFactorSelectionUrl", "/mfa/select-factor"));
            payload.put("message", "Please select an authentication factor.");
        } else {
            log.info("[ChallengeGenerator] Challenge generation called for MFA state {} where no specific client challenge is typically generated. Session ID: {}", state, ctx.getMfaSessionId());
            payload.put("mode", "INFO");
            payload.put("message", "Current MFA state (" + state + ") does not require a specific client challenge via this generator.");
            payload.put("currentState", state.name());
        }
        return payload;
    }

    /**
     * Helper method to safely cast FactorAuthenticationOptions to a specific type or return a default.
     * Logs warnings if types mismatch or if options are unexpectedly null.
     */
    private <T extends FactorAuthenticationOptions> T getTypedOptions(
            FactorAuthenticationOptions options,
            Class<T> expectedType,
            T defaultOptions, // 기본값으로 사용할 옵션 객체
            String factorNameForLog,
            String sessionIdForLog) {

        if (expectedType.isInstance(options)) {
            return expectedType.cast(options);
        }

        if (options != null) { // 타입은 안 맞지만, null은 아닌 경우
            log.warn("[ChallengeGenerator] Type mismatch for factor options. Expected: {}, Actual: {}. Factor: {}. Session ID: {}. Attempting to use default options if available.",
                    expectedType.getSimpleName(), options.getClass().getSimpleName(), factorNameForLog, sessionIdForLog);
        } else { // options 자체가 null인 경우
            log.warn("[ChallengeGenerator] FactorAuthenticationOptions were null for factor {}. Session ID: {}. Attempting to use default options if available.",
                    factorNameForLog, sessionIdForLog);
        }

        if (defaultOptions == null && factorNameForLog.equals("PASSKEY")) {
            log.error("[ChallengeGenerator] Default options are null for required factor {}. This will likely lead to errors. Session ID: {}",
                    factorNameForLog, sessionIdForLog);
        } else if (defaultOptions == null) {
            log.warn("[ChallengeGenerator] Default options are null for factor {}. Session ID: {}",
                    factorNameForLog, sessionIdForLog);
        }
        return defaultOptions;
    }
}


