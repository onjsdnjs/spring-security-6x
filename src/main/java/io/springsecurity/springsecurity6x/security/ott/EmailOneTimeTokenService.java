package io.springsecurity.springsecurity6x.security.ott;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.ott.*;
import org.springframework.stereotype.Service;

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

        OneTimeToken token = delegate.generate(request);
        String email = request.getUsername();
        String loginUrl = baseUrl + loginPath;

        // 3) 이메일 본문 작성 및 발송
        // HTML 이메일 본문: 폼+버튼+JS
        String html = String.format(
                "<html>" +
                        "<body>" +
                        "<form id=\"magicLinkForm\" action=\"%s\" method=\"post\" style=\"display:none;\">" +
                        "<input type=\"hidden\" name=\"username\" value=\"%s\"/>" +
                        "<input type=\"hidden\" name=\"token\"    value=\"%s\"/>" +
                        "</form>" +
                        "<button id=\"magicLinkButton\" style=\"padding:10px 20px;background:#1976d2;color:#fff;" +
                        "border:none;border-radius:4px;cursor:pointer;\">로그인하기</button>" +
                        "<script>" +
                        "document.getElementById('magicLinkButton').addEventListener('click', function() {" +
                        "document.getElementById('magicLinkForm').submit();});" +
                        "</script>" +
                        "</body>" +
                        "</html>",
                loginUrl,
                email,
                token.getTokenValue()
        );
        emailService.sendHtmlMessage(request.getUsername(), "[스프링 시큐리티] OTT 로그인 링크", html);

        return token;
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
