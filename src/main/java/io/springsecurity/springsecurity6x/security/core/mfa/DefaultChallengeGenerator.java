package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.dsl.option.*;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

@Slf4j
public class DefaultChallengeGenerator implements ChallengeGenerator {

    @Override
    public Map<String, Object> generate(FactorContext ctx) {
        Objects.requireNonNull(ctx, "FactorContext cannot be null.");

        MfaState state = ctx.getCurrentState();
        AuthType currentFactorType = ctx.getCurrentProcessingFactor();
        AuthenticationProcessingOptions currentFactorOptions = ctx.getCurrentFactorOptions();

        Map<String, Object> payload = new HashMap<>();

        if (state == null) {
            log.error("[ChallengeGenerator] MFA state is null. Session ID: {}.", ctx.getMfaSessionId());
            payload.put("error", "MFA_STATE_NULL");
            payload.put("message", "MFA state is missing.");
            return payload;
        }

        if (state == MfaState.FACTOR_CHALLENGE_INITIATED) {
            if (currentFactorType == null) {
                log.error("[ChallengeGenerator] Current processing factor is not set for state: {} and session ID: {}.", state, ctx.getMfaSessionId());
                payload.put("error", "FACTOR_TYPE_MISSING");
                payload.put("message", "Current authentication factor type is not set.");
                return payload;
            }

            payload.put("factorType", currentFactorType.name());
            log.debug("[ChallengeGenerator] Generating challenge for factorType: {}, state: {}, session ID: {}", currentFactorType, state, ctx.getMfaSessionId());

            switch (currentFactorType) {
                case FORM:
                    // getTypedOptions 헬퍼 사용 또는 직접 캐스팅 및 null 체크
                    if (currentFactorOptions instanceof FormOptions formOpts) {
                        payload.put("mode", "FORM_SUBMISSION_REQUIRED");
                        payload.put("loginPageUrl", formOpts.getLoginPage());
                        payload.put("processingUrl", formOpts.getLoginProcessingUrl());
                        payload.put("usernameParameter", formOpts.getUsernameParameter());
                        payload.put("passwordParameter", formOpts.getPasswordParameter());
                        payload.put("fields", List.of(
                                Objects.toString(formOpts.getUsernameParameter(), "username"),
                                Objects.toString(formOpts.getPasswordParameter(), "password")
                        ));
                    } else {
                        handleOptionTypeError(payload, AuthType.FORM, currentFactorOptions, ctx.getMfaSessionId());
                    }
                    break;

                case REST:
                    if (currentFactorOptions instanceof RestOptions restOpts) {
                        payload.put("mode", "API_CREDENTIAL_SUBMISSION_REQUIRED");
                        payload.put("url", restOpts.getLoginProcessingUrl());
                        payload.put("method", "POST");
                        payload.put("bodySchema", Map.of(
                                Objects.toString(restOpts.getUsernameParameter(), "username"), "string",
                                Objects.toString(restOpts.getPasswordParameter(), "password"), "string"
                        ));
                    } else {
                        handleOptionTypeError(payload, AuthType.REST, currentFactorOptions, ctx.getMfaSessionId());
                    }
                    break;

                case OTT:
                    if (currentFactorOptions instanceof OttOptions ottOpts) {
                        payload.put("mode", "OTT_CODE_REQUIRED");
                        payload.put("generationUrl", ottOpts.getTokenGeneratingUrl());
                        payload.put("submitUrl", ottOpts.getLoginProcessingUrl());
                        payload.put("submitField", Objects.toString(ottOpts.getTokenParameterName(), "token"));
                    } else {
                        handleOptionTypeError(payload, AuthType.OTT, currentFactorOptions, ctx.getMfaSessionId());
                    }
                    break;

                case PASSKEY:
                    if (currentFactorOptions instanceof PasskeyOptions passkeyOpts) {
                        payload.put("mode", "PASSKEY_AUTHENTICATION_REQUIRED");
                        payload.put("assertionOptionsUrl", passkeyOpts.getAssertionOptionsEndpoint());
                        payload.put("assertionVerificationUrl", passkeyOpts.getLoginProcessingUrl());
                        payload.put("rpId", passkeyOpts.getRpId());
                        // allowedOrigins도 필요시 추가: payload.put("allowedOrigins", passkeyOpts.getAllowedOrigins());


                        Object webAuthnOptions = ctx.getChallengePayload("publicKeyCredentialRequestOptions");
                        if (webAuthnOptions != null) {
                            payload.put("options", webAuthnOptions);
                        } else {
                            log.warn("[ChallengeGenerator] No pre-generated WebAuthn options in FactorContext for PASSKEY. Client should fetch from assertionOptionsUrl. Session ID: {}", ctx.getMfaSessionId());
                            payload.put("options", Collections.emptyMap()); // 또는 options 필드 생략
                        }
                    } else {
                        handleOptionTypeError(payload, AuthType.PASSKEY, currentFactorOptions, ctx.getMfaSessionId());
                    }
                    break;
                // case RECOVERY_CODE:
                // if (currentFactorOptions instanceof RecoveryCodeOptions recoveryOpts) { ... }
                // break;
                default:
                    log.error("[ChallengeGenerator] Unsupported factor type {} for challenge generation in state {} for session ID: {}", currentFactorType, state, ctx.getMfaSessionId());
                    payload.put("error", "UNSUPPORTED_FACTOR");
                    payload.put("message", "Challenge generation for factor type " + currentFactorType + " is not supported.");
                    return payload;
            }
        } else if (state == MfaState.AWAITING_MFA_FACTOR_SELECTION) {
            log.debug("[ChallengeGenerator] Generating payload for factor selection. Session ID: {}", ctx.getMfaSessionId());
            payload.put("mode", "FACTOR_SELECTION_REQUIRED");
            payload.put("message", "Please select an authentication factor.");
            // 사용 가능한 factor 목록 (ctx.getRegisteredMfaFactors() 등 활용) 전달 가능
            // payload.put("availableFactors", ctx.getRegisteredMfaFactors().stream().map(AuthType::name).toList());
        } else {
            log.info("[ChallengeGenerator] Challenge generation called for MFA state {} where no specific client challenge is typically generated. Session ID: {}", state, ctx.getMfaSessionId());
            payload.put("mode", "INFO");
            payload.put("message", "Current MFA state (" + state + ") does not require a specific client challenge via this generator.");
            payload.put("currentState", state.name());
        }
        return payload;
    }

    private void handleOptionTypeError(Map<String, Object> payload, AuthType expectedAuthType, AuthenticationProcessingOptions actualOptions, String sessionId) {
        String actualType = actualOptions != null ? actualOptions.getClass().getName() : "null";
        log.error("[ChallengeGenerator] Type mismatch or null options for factor {}. Expected a subclass of {} but got {}. Session ID: {}",
                expectedAuthType, AuthenticationProcessingOptions.class.getSimpleName(), actualType, sessionId);
        payload.put("error", "INTERNAL_CONFIGURATION_ERROR");
        payload.put("message", "Internal server error: Incorrect options type for " + expectedAuthType);
    }

    // getTypedOptions 헬퍼 메소드는 삭제하거나, AuthenticationProcessingOptions 기반으로 수정.
    // 여기서는 직접 instanceof 와 캐스팅을 사용하는 방식으로 변경.
}


