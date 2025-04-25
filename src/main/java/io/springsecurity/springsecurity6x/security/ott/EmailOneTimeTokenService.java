package io.springsecurity.springsecurity6x.security.ott;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.ott.*;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Service
@RequiredArgsConstructor
public class EmailOneTimeTokenService implements OneTimeTokenService {

    private final InMemoryOneTimeTokenService delegate = new InMemoryOneTimeTokenService();
    private final EmailService emailService;

    @Value("${app.url.base:http://localhost:8080}")
    private String baseUrl;

    @Value("${app.url.login-path:/login/ott}")
    private String loginPath;

    @Override
    public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
        // 1) 토큰 생성
        OneTimeToken oneTimeToken = delegate.generate(request);

        // 2) 로그인 링크 생성
        String loginLink = UriComponentsBuilder
                .fromHttpUrl(baseUrl)
                .path(loginPath)
                .queryParam("username", URLEncoder.encode(request.getUsername(), StandardCharsets.UTF_8))
                .queryParam("token", URLEncoder.encode(oneTimeToken.getTokenValue(), StandardCharsets.UTF_8))
                .build(true)
                .toUriString();

        // 3) 이메일 본문 작성 및 발송
        String html = String.format(
                "<p>안녕하세요,</p>" +
                        "<p>아래 버튼을 클릭하시면 OTT 방식으로 자동 로그인됩니다:</p>" +
                        "<p><a href=\"%s\" style=\"display:inline-block;padding:10px 20px;" +
                        "background-color:#1976d2;color:#fff;text-decoration:none;" +
                        "border-radius:4px;\">로그인하기</a></p><br/><p>감사합니다.</p>",
                loginLink
        );
        emailService.sendHtmlMessage(request.getUsername(), "[스프링 시큐리티] OTT 로그인 링크", html);

        return oneTimeToken;
    }

    @Override
    public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
        // 토큰 검증 및 삭제까지 위임
        return delegate.consume(authenticationToken);
    }

    public void setClock(java.time.Clock clock) {
        // 테스트용: 토큰 만료 시간 조절
        delegate.setClock(clock);
    }
}
