package io.springsecurity.springsecurity6x.security.core.validator;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

@Slf4j
public class RequiredPlatformOptionsValidator implements Validator<AuthenticationStepConfig> {

    @Override
    public ValidationResult validate(AuthenticationStepConfig step) {
        ValidationResult result = new ValidationResult();
        if (step == null || step.getOptions() == null) {
            return result;
        }

        String stepIdentifier = String.format("Step (type: '%s', order: %d)", step.getType(), step.getOrder());
        Object optionsObject = step.getOptions().get("_options");

        if ("passkey".equalsIgnoreCase(step.getType())) {
            if (!(optionsObject instanceof PasskeyOptions passkeyOptions)) {
                result.addError(String.format("치명적 오류: %s의 옵션 객체가 PasskeyOptions 타입이 아닙니다. (실제 타입: %s)",
                        stepIdentifier, optionsObject != null ? optionsObject.getClass().getName() : "null"));
            } else {
                if (!StringUtils.hasText(passkeyOptions.getRpId())) {
                    result.addError(String.format("치명적 오류: %s에 필수 플랫폼 옵션인 'rpId'가 설정되지 않았습니다. Passkey 인증은 Relying Party ID가 반드시 필요합니다.", stepIdentifier));
                }
                // rpName은 필수는 아니지만 없으면 경고
                if (!StringUtils.hasText(passkeyOptions.getRpName())) {
                    result.addWarning(String.format("설정 경고: %s에 'rpName'이 설정되지 않았습니다. 사용자에게 표시될 Relying Party 이름입니다.", stepIdentifier));
                }
            }
        }
        // 다른 인증 방식에 대한 플랫폼 필수 옵션 검사 추가 (예: OAuth2 클라이언트 ID/Secret 등)

        if (result.hasErrors() || result.hasWarnings()){
            log.warn("DSL VALIDATION for {}: Errors: {}, Warnings: {}", stepIdentifier, result.getErrors(), result.getWarnings());
        }
        return result;
    }
}
