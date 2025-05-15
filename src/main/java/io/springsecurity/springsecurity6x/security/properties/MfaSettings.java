package io.springsecurity.springsecurity6x.security.properties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MfaSettings {
    /**
     * 1차 인증 성공 후 MFA가 필요할 때 클라이언트가 다음 단계를 시작하기 위해 호출할 URL.
     * 예: /mfa, /mfa/initiate
     */
    private String initiateUrl = "/mfa"; // 기본값 설정
}
