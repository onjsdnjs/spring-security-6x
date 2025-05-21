package io.springsecurity.springsecurity6x.security.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.NestedConfigurationProperty; // 추가

@Getter
@Setter
public class MfaSettings {
    /**
     * 1차 인증 성공 후 MFA가 필요할 때 클라이언트가 다음 단계를 시작하기 위해 호출할 URL.
     * 예: /mfa/initiate 또는 /mfa/select-factor
     */
    private String initiateUrl = "/mfa/initiate"; // MfaContinuationFilter가 처리

    /**
     * MFA 인증 단계에서 사용자가 인증 수단을 선택하는 UI 페이지 URL
     */
    private String selectFactorUrl = "/mfa/select-factor";

    /**
     * MFA 실패 시 기본적으로 이동할 URL
     */
    private String failureUrl = "/mfa/failure";

    /**
     * MFA OTT 코드의 유효 시간 (초 단위)
     */
    private int otpTokenValiditySeconds = 300; // 기본 5분

    /**
     * MFA Passkey 팩터 설정
     */
    @NestedConfigurationProperty
    private PasskeyFactorSettings passkeyFactor = new PasskeyFactorSettings();

    @NestedConfigurationProperty
    private OttFactorSettings ottFactor = new OttFactorSettings();

}