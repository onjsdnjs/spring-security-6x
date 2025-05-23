package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.dsl.option.*;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.util.*;

@Slf4j
public class DefaultChallengeGenerator implements ChallengeGenerator {

    @Override
    public Map<String, Object> generate(FactorContext ctx) {
        Objects.requireNonNull(ctx, "FactorContext cannot be null.");

        MfaState state = ctx.getCurrentState();
        AuthType currentFactorType = ctx.getCurrentProcessingFactor();
        // FactorContext 로부터 현재 Factor의 옵션을 가져옴
        AuthenticationProcessingOptions currentFactorOptions = ctx.getCurrentFactorOptions();

        Map<String, Object> payload = new HashMap<>();

        if (state == null) {
            log.error("[ChallengeGenerator] MFA state is null. Session ID: {}.", ctx.getMfaSessionId());
            payload.put("error", "MFA_STATE_NULL");
            payload.put("message", "MFA state is missing.");
            return payload;
        }

        // 상태가 FACTOR_CHALLENGE_INITIATED 일 때만 구체적인 Factor 챌린지 생성
        // MfaContinuationFilter에서 AWAITING_FACTOR_CHALLENGE_INITIATION -> FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION 으로 변경하므로,
        // ChallengeGenerator가 호출되는 시점의 상태는 AWAITING_FACTOR_CHALLENGE_INITIATION 또는
        // MfaContinuationFilter에서 상태 변경 후 challenge UI 렌더링 직전일 수 있음.
        // 여기서는 UI 렌더링에 필요한 정보를 생성하므로, 챌린지 UI 로드 직전 상태인
        // AWAITING_FACTOR_CHALLENGE_INITIATION 에서 주로 호출된다고 가정.
        // 또는, MfaContinuationFilter에서 FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION 로 변경하고
        // 이 상태에서 ChallengeGenerator를 호출하여 UI에 필요한 정보를 내려줄 수도 있음.
        // 현재 MfaState.FACTOR_CHALLENGE_INITIATED 사용 부분은 MfaState enum 정의와 동기화 필요.
        // MfaState.java 에 FACTOR_CHALLENGE_INITIATED 가 있으므로, 해당 상태를 기준으로 함.
        if (state == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION || state == MfaState.FACTOR_CHALLENGE_INITIATED) {
            if (currentFactorType == null) {
                log.error("[ChallengeGenerator] Current processing factor is not set for state: {} and session ID: {}.", state, ctx.getMfaSessionId());
                payload.put("error", "FACTOR_TYPE_MISSING");
                payload.put("message", "Current authentication factor type is not set.");
                return payload;
            }

            // currentFactorOptions가 null인 경우에 대한 방어 코드 추가
            if (currentFactorOptions == null && currentFactorType != null) {
                log.warn("[ChallengeGenerator] currentFactorOptions is null for factorType: {} in state: {}. Session ID: {}. Challenge generation may be incomplete.", currentFactorType, state, ctx.getMfaSessionId());
                // 특정 Factor (예: RECOVERY_CODE)는 별도의 옵션 객체가 없을 수도 있으므로, null을 허용하거나,
                // 각 case에서 null 체크를 더 강화해야 함.
                // 여기서는 handleOptionTypeError를 호출하지 않고, 각 case에서 옵션이 필요한 경우에만 사용하도록 함.
            }


            payload.put("factorType", currentFactorType.name());
            log.debug("[ChallengeGenerator] Generating challenge for factorType: {}, state: {}, session ID: {}", currentFactorType, state, ctx.getMfaSessionId());

            switch (currentFactorType) {
                case FORM:
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
                    } else if (currentFactorOptions != null) { // 옵션이 있지만 타입이 안맞는 경우
                        handleOptionTypeError(payload, AuthType.FORM, currentFactorOptions, ctx.getMfaSessionId());
                    } else { // 옵션 자체가 없는 경우 (FORM은 옵션이 필수적임)
                        log.error("[ChallengeGenerator] FormOptions are null for FORM factor. Session ID: {}", ctx.getMfaSessionId());
                        payload.put("error", "FORM_OPTIONS_MISSING");
                        payload.put("message", "Form authentication options are missing.");
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
                    } else if (currentFactorOptions != null) {
                        handleOptionTypeError(payload, AuthType.REST, currentFactorOptions, ctx.getMfaSessionId());
                    } else {
                        log.error("[ChallengeGenerator] RestOptions are null for REST factor. Session ID: {}", ctx.getMfaSessionId());
                        payload.put("error", "REST_OPTIONS_MISSING");
                        payload.put("message", "REST authentication options are missing.");
                    }
                    break;

                case OTT:
                    if (currentFactorOptions instanceof OttOptions ottOpts) {
                        payload.put("mode", "OTT_CODE_REQUIRED");
                        payload.put("generationUrl", ottOpts.getTokenGeneratingUrl()); // 클라이언트가 OTT 코드 재생성 요청 시 사용
                        payload.put("submitUrl", ottOpts.getLoginProcessingUrl()); // OTT 코드 제출 URL
                        // MfaContinuationFilter에서 이미 OTT 코드 생성을 요청하므로, 여기서는 추가적인 생성 로직 불필요.
                        // 클라이언트(JS)는 mfa-verify-ott.html에서 이 정보를 사용하여 UI를 구성하고, 코드 재전송 시 generationUrl 사용 가능.
                    } else if (currentFactorOptions != null) {
                        handleOptionTypeError(payload, AuthType.OTT, currentFactorOptions, ctx.getMfaSessionId());
                    } else {
                        log.error("[ChallengeGenerator] OttOptions are null for OTT factor. Session ID: {}", ctx.getMfaSessionId());
                        payload.put("error", "OTT_OPTIONS_MISSING");
                        payload.put("message", "OTT authentication options are missing.");
                    }
                    break;

                case PASSKEY:
                    if (currentFactorOptions instanceof PasskeyOptions passkeyOpts) {
                        payload.put("mode", "PASSKEY_AUTHENTICATION_REQUIRED");
                        // 클라이언트 JS는 이 URL로 assertion options를 요청해야 함 (예: /api/mfa/assertion/options)
                        payload.put("assertionOptionsUrl", passkeyOpts.getAssertionOptionsEndpoint());
                        // 클라이언트 JS는 assertion 생성 후 이 URL로 검증 요청
                        payload.put("assertionVerificationUrl", passkeyOpts.getLoginProcessingUrl());
                        payload.put("rpId", passkeyOpts.getRpId());

                        // MfaContinuationFilter에서 Passkey challenge UI로 가기 전에
                        // Assertion Options를 미리 생성하여 FactorContext에 저장해두었다면 여기서 사용.
                        // Object webAuthnOptions = ctx.getAttribute("publicKeyCredentialRequestOptions");
                        // if (webAuthnOptions != null) {
                        //     payload.put("options", webAuthnOptions);
                        // } else {
                        //     log.warn("[ChallengeGenerator] No pre-generated WebAuthn options in FactorContext for PASSKEY. Client should fetch from assertionOptionsUrl. Session ID: {}", ctx.getMfaSessionId());
                        //     // options 필드를 비워두거나, 클라이언트가 assertionOptionsUrl에서 가져오도록 안내
                        // }
                        // 현재 MfaApiController가 /api/mfa/assertion/options 엔드포인트를 제공하므로,
                        // 클라이언트(mfa-verify-passkey.js)가 이 URL을 호출하여 options를 가져오는 것이 적절.
                        // 따라서 여기서 options를 직접 내려주지 않아도 됨.
                        log.debug("[ChallengeGenerator] For PASSKEY, client should fetch assertion options from: {}", passkeyOpts.getAssertionOptionsEndpoint());

                    } else if (currentFactorOptions != null) {
                        handleOptionTypeError(payload, AuthType.PASSKEY, currentFactorOptions, ctx.getMfaSessionId());
                    } else {
                        log.error("[ChallengeGenerator] PasskeyOptions are null for PASSKEY factor. Session ID: {}", ctx.getMfaSessionId());
                        payload.put("error", "PASSKEY_OPTIONS_MISSING");
                        payload.put("message", "Passkey authentication options are missing.");
                    }
                    break;
                // case RECOVERY_CODE:
                // ...
                default:
                    log.error("[ChallengeGenerator] Unsupported factor type {} for challenge generation in state {} for session ID: {}", currentFactorType, state, ctx.getMfaSessionId());
                    payload.put("error", "UNSUPPORTED_FACTOR");
                    payload.put("message", "Challenge generation for factor type " + currentFactorType + " is not supported.");
                    return payload;
            }
        } else if (state == MfaState.AWAITING_FACTOR_SELECTION) {
            log.debug("[ChallengeGenerator] Generating payload for factor selection. Session ID: {}", ctx.getMfaSessionId());
            payload.put("mode", "FACTOR_SELECTION_REQUIRED");
            payload.put("message", "Please select an authentication factor.");
            if (ctx.getRegisteredMfaFactors() != null && !ctx.getRegisteredMfaFactors().isEmpty()) {
                payload.put("availableFactors", ctx.getRegisteredMfaFactors().stream().map(AuthType::name).toList());
            } else {
                payload.put("availableFactors", Collections.emptyList());
                log.warn("[ChallengeGenerator] No registered MFA factors found in FactorContext for factor selection. Session ID: {}", ctx.getMfaSessionId());
            }
        } else {
            log.info("[ChallengeGenerator] Challenge generation called for MFA state {} where no specific client challenge is typically generated. Session ID: {}", state, ctx.getMfaSessionId());
            payload.put("mode", "INFO");
            payload.put("message", "Current MFA state (" + state + ") does not require a specific client challenge via this generator.");
            payload.put("currentState", state.name());
        }
        return payload;
    }

    private void handleOptionTypeError(Map<String, Object> payload, AuthType expectedAuthType, @Nullable AuthenticationProcessingOptions actualOptions, String sessionId) {
        String actualType = actualOptions != null ? actualOptions.getClass().getName() : "null";
        log.error("[ChallengeGenerator] Type mismatch or null options for factor {}. Expected a subclass of {} but got {}. Session ID: {}",
                expectedAuthType, AuthenticationProcessingOptions.class.getSimpleName(), actualType, sessionId);
        payload.put("error", "INTERNAL_CONFIGURATION_ERROR");
        payload.put("message", "Internal server error: Incorrect options type for " + expectedAuthType);
    }
}