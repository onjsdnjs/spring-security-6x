package io.springsecurity.springsecurity6x.security.properties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MfaSettings {
    /**
     * 1차 인증 성공 후 MFA가 필요할 때 클라이언트가 다음 단계를 시작하기 위해 호출할 URL.
     * 예: /mfa/select-factor
     */
    private String initiateUrl = "/mfa/select-factor"; // 기본값 변경 및 명확화

    /**
     * MFA 실패 시 기본적으로 이동할 URL
     */
    private String failureUrl = "/mfa/failure";

    /**
     * MFA OTT 코드의 유효 시간 (초 단위)
     */
    private int otpTokenValiditySeconds = 300; // 기본 5분

    public String getSelectFactorUrl() {
        return null;
    }
}
