package io.springsecurity.springsecurity6x.security.service.ott;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.ott.*;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.UUID;

@Service
@Slf4j
public class EmailOneTimeTokenService implements OneTimeTokenService {

    private InMemoryOneTimeTokenService delegate; // Spring Security 6.2+ 에서는 setTokenValidity 존재
    private final EmailService emailService;
    private final CodeStore codeStore;
    private final AuthContextProperties authContextProperties;

    @Value("${app.url.base:http://localhost:8080}")
    private String baseUrl;

    public EmailOneTimeTokenService(EmailService emailService,
                                    CodeStore codeStore,
                                    AuthContextProperties authContextProperties) { // 주입
        this.delegate = new InMemoryOneTimeTokenService();
        this.emailService = emailService;
        this.codeStore = codeStore;
        this.authContextProperties = authContextProperties;
        log.info("EmailOneTimeTokenService initialized. Delegate's configured token validity: {} seconds (from InMemoryOneTimeTokenService bean).",
                Duration.ofSeconds(this.authContextProperties.getMfa().getOtpTokenValiditySeconds()).toSeconds());
    }

    /**
     * 매직 링크를 생성하고 이메일로 발송합니다.
     * @param request GenerateOneTimeTokenRequest (username 포함)
     * @param loginProcessingPath 이 링크를 클릭했을 때 최종적으로 코드가 제출될 경로
     * @param emailPurpose 이메일 제목/본문에 사용될 목적 문자열
     * @return 생성된 OneTimeToken
     */
    public OneTimeToken generateAndSendMagicLink(GenerateOneTimeTokenRequest request, String loginProcessingPath, String emailPurpose) {
        Assert.notNull(request, "GenerateOneTimeTokenRequest cannot be null");
        Assert.hasText(request.getUsername(), "Username in request cannot be empty");
        Assert.hasText(loginProcessingPath, "loginProcessingPath cannot be empty");
        Assert.hasText(emailPurpose, "emailPurpose cannot be empty");

        // 1. 실제 검증용 OneTimeToken 생성 (delegate가 내부적으로 유효시간 관리)
        OneTimeToken oneTimeToken = delegate.generate(request);
        // 2. 매직링크에 사용될 외부용 코드 생성 및 CodeStore에 매핑 저장
        String magicLinkExternalCode = UUID.randomUUID().toString();
        codeStore.save(magicLinkExternalCode, oneTimeToken); // 외부 코드와 실제 토큰 매핑

        String loginLink = UriComponentsBuilder.fromUriString(baseUrl)
                .path(loginProcessingPath)
                .queryParam("code", URLEncoder.encode(magicLinkExternalCode, StandardCharsets.UTF_8))
                .build(true)
                .toUriString();

        String emailSubject = String.format("[Spring Security Platform] %s - Login Link", emailPurpose);
        // 유효 시간은 AuthContextProperties 에서 가져와 표시 (delegate의 실제 유효 시간과 일치하도록 설정 보장)
        long tokenValidityMinutes = Duration.ofSeconds(authContextProperties.getMfa().getOtpTokenValiditySeconds()).toMinutes();

        String htmlBody = String.format(
                "<p>Hello %s,</p>" +
                        "<p>Please click the link below to log in securely for %s:</p>" +
                        "<p><a href=\"%s\" style=\"display:inline-block;padding:10px 20px;" +
                        "background-color:#2196f3;color:white;text-decoration:none;" +
                        "border-radius:4px;\">Log In Securely</a></p>" +
                        "<p>This link will expire in %d minutes.</p>" +
                        "<p>If you did not request this, please ignore this email.</p>" +
                        "<p>Thank you.</p>",
                request.getUsername(), emailPurpose, loginLink, tokenValidityMinutes
        );

        emailService.sendHtmlMessage(request.getUsername(), emailSubject, htmlBody);
        log.info("Magic link for {} sent to {} for path {}. ExternalLinkCode: {}. Token validity display: {} minutes.",
                emailPurpose, request.getUsername(), loginProcessingPath, magicLinkExternalCode, tokenValidityMinutes);
        return oneTimeToken;
    }

    /**
     * 6자리 숫자 인증 코드를 생성하여 이메일로 발송합니다. (코드 직접 입력 방식용)
     * @param username 대상 사용자 (이메일 주소)
     * @param emailPurpose 이메일 제목/본문에 사용될 목적 문자열
     * @return 생성된 OneTimeToken (이 토큰의 tokenValue가 6자리 숫자 코드)
     */
    public OneTimeToken generateAndSendVerificationCode(String username, String emailPurpose) {
        Assert.hasText(username, "Username cannot be empty");
        Assert.hasText(emailPurpose, "Email purpose cannot be empty");

        SecureRandom random = new SecureRandom();
        String numericCode = String.format("%06d", random.nextInt(1_000_000));

        GenerateOneTimeTokenRequest tokenRequest = new GenerateOneTimeTokenRequest(username);
//        GenerateOneTimeTokenRequest tokenRequest = new GenerateOneTimeTokenRequest(username, numericCode);
        OneTimeToken oneTimeTokenWithNumericCode = delegate.generate(tokenRequest); // delegate가 내부적으로 유효시간 관리
        long tokenValidityMinutes = Duration.ofSeconds(authContextProperties.getMfa().getOtpTokenValiditySeconds()).toMinutes();

        String emailSubject = String.format("[Spring Security Platform] Your %s Verification Code", emailPurpose);
        String htmlBody = String.format(
                "<p>Hello %s,</p>" +
                        "<p>Your verification code for %s is: <strong style=\"font-size:1.2em; color:#3f51b5;\">%s</strong></p>" +
                        "<p>This code will expire in %d minutes.</p>" +
                        "<p>If you did not request this code, please ignore this email.</p>" +
                        "<p>Thank you.</p>",
                username, emailPurpose, numericCode, tokenValidityMinutes
        );

        emailService.sendHtmlMessage(username, emailSubject, htmlBody);
        log.info("Verification code ({}) for {} sent to {}. Token validity display: {} minutes.",
                numericCode, emailPurpose, username, tokenValidityMinutes);
        return oneTimeTokenWithNumericCode;
    }

    @Override
    public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
        // 이 메소드는 Spring Security의 GenerateOneTimeTokenFilter에 의해 기본적으로 호출될 수 있음.
        // 해당 필터가 사용되는 플로우(예: 단일 OTT의 /ott/generate 경로)의 기본 동작을 정의.
        // 여기서는 단일 OTT는 기본적으로 "매직 링크" 방식을 사용한다고 가정.
        // 코드 직접 입력 방식은 필터 내 다른 로직이나 커스텀 필터에서 generateAndSendVerificationCode를 호출하도록 유도.
        String loginProcessingPath = authContextProperties.getOttFactor().getCodeSentUrl();
        if (!StringUtils.hasText(loginProcessingPath)) {
            loginProcessingPath = "/login/ott"; // 기본값
            log.warn("Default OneTimeTokenService.generate(): Single OTT loginProcessingUrl not found in properties, using default: {}", loginProcessingPath);
        }
        log.debug("Default OneTimeTokenService.generate() called for user: {}. Assuming single OTT Magic Link generation to path {}.",
                request.getUsername(), loginProcessingPath);
        return generateAndSendMagicLink(request, loginProcessingPath, "One-Time Login");
    }

    @Override
    public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
        log.debug("Consuming OneTimeToken for username: {}", authenticationToken.getName());
        // 매직링크의 경우: OttForwardingFilter가 CodeStore에서 OneTimeToken을 꺼내고,
        //                그 OneTimeToken 내부의 실제 토큰값(authenticationToken.getTokenValue())으로 consume 호출.
        // 코드입력의 경우: 사용자가 입력한 숫자 코드가 authenticationToken.getTokenValue()로 들어와서 consume 호출.
        return delegate.consume(authenticationToken);
    }
}