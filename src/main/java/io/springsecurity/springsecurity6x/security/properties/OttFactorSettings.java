package io.springsecurity.springsecurity6x.security.properties;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OttFactorSettings {
    private String requestCodeUiUrl = "/mfa/ott/request-code-ui"; // 이메일 확인 및 코드 요청 UI (GET)
    private String codeGenerationUrl = "/mfa/ott/generate-code";  // 코드 생성 요청 처리 경로 (POST, Spring Security Filter)
    private String codeSentUrl = "/mfa/ott/code-sent";          // 코드 발송 완료 안내 UI (GET)
    private String challengeUrl = "/mfa/challenge/ott";       // 코드 입력 UI (GET) 및 코드 검증 처리 경로 (POST, Spring Security Filter)
    private String defaultFailureUrl = "/mfa/challenge/ott?error"; // OTT 검증 실패 시 기본 리다이렉션 URL
}

