package io.springsecurity.springsecurity6x.security.ott;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.ott.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;

public class EmailOneTimeTokenService implements OneTimeTokenService {

    private InMemoryOneTimeTokenService delegate;
    private EmailService emailService;

    @Value("${app.url.base:http://localhost:8080}")
    private String baseUrl;
    @Value("${app.url.login-path:/login/ott}")
    private String loginPath;

    public EmailOneTimeTokenService(InMemoryOneTimeTokenService delegate, EmailService emailService) {
        this.delegate = delegate;
        this.emailService = emailService;
    }

    @Override
    public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
        // 1) 토큰 생성
        OneTimeToken oneTimeToken = delegate.generate(request);

        // 2) 토큰 문자열 추출
        String tokenValue = oneTimeToken.getTokenValue();

        // 3) 로그인 링크 조합
        String loginLink = String.format("%s%s?username=%s&token=%s",
                baseUrl, loginPath,
                URLEncoder.encode(request.getUsername(), StandardCharsets.UTF_8),
                URLEncoder.encode(tokenValue, StandardCharsets.UTF_8));

        // 4) 이메일 발송
        String html = """
            <p>안녕하세요,</p>
            <p>아래 버튼을 클릭하시면 자동 로그인됩니다:</p>
            <p><a href="%s">로그인하기</a></p>
            """.formatted(loginLink);
        emailService.sendHtmlMessage(request.getUsername(), "로그인 링크", html);

        return oneTimeToken;
    }

    @Override
    public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
        // 인증 필터가 호출할 때 토큰 검증 및 제거까지 위임
        return delegate.consume(authenticationToken);
    }

    public void setClock(Clock clock) {
        // (선택) 토큰 만료 테스트를 위해 Clock 설정 가능
        delegate.setClock(clock);
    }
}
