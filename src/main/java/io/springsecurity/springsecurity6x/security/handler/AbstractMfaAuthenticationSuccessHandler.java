package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult;
import io.springsecurity.springsecurity6x.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * MFA 인증 성공 처리 핸들러
 *
 * 토큰 발급과 응답 처리를 담당하며, 사용자 커스텀 로직을 위한 확장점 제공
 */
@Slf4j
public abstract class AbstractMfaAuthenticationSuccessHandler implements PlatformAuthenticationSuccessHandler {

    protected final TokenService tokenService;
    protected final AuthResponseWriter responseWriter;
    protected final MfaSessionRepository sessionRepository;
    protected final MfaStateMachineIntegrator stateMachineIntegrator;
    protected final AuthContextProperties authContextProperties;
    private final RequestCache requestCache = new HttpSessionRequestCache();
    private PlatformAuthenticationSuccessHandler delegateHandler;

    protected AbstractMfaAuthenticationSuccessHandler(TokenService tokenService,
                                                      AuthResponseWriter responseWriter,
                                                      MfaSessionRepository sessionRepository,
                                                      MfaStateMachineIntegrator stateMachineIntegrator,
                                                      AuthContextProperties authContextProperties) {
        this.tokenService = tokenService;
        this.responseWriter = responseWriter;
        this.sessionRepository = sessionRepository;
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.authContextProperties = authContextProperties;
    }

    public void setDelegateHandler(@Nullable PlatformAuthenticationSuccessHandler delegateHandler) {
        this.delegateHandler = delegateHandler;
        if (delegateHandler != null) {
            log.info("Delegate handler set: {}", delegateHandler.getClass().getName());
        }
    }

    /**
     * 최종 인증 성공 처리 - 플랫폼 핵심 로직
     */
    protected final void handleFinalAuthenticationSuccess(HttpServletRequest request,
                                                          HttpServletResponse response,
                                                          Authentication finalAuthentication,
                                                          @Nullable FactorContext factorContext) throws IOException {

        if (response.isCommitted()) {
            log.warn("Response already committed for user: {}", finalAuthentication.getName());
            return;
        }

        // 1. 토큰 생성
        String deviceId = factorContext != null ? (String) factorContext.getAttribute("deviceId") : null;
        String accessToken = tokenService.createAccessToken(finalAuthentication, deviceId);
        String refreshToken = null;
        if (tokenService.properties().isEnableRefreshToken()) {
            refreshToken = tokenService.createRefreshToken(finalAuthentication, deviceId);
        }

        // 2. 세션 정리
        if (factorContext != null && factorContext.getMfaSessionId() != null) {
            stateMachineIntegrator.releaseStateMachine(factorContext.getMfaSessionId());
            sessionRepository.removeSession(factorContext.getMfaSessionId(), request, response);
        }

        // 3. 토큰 전송 정보 준비
        TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshToken);

        // 4. 응답 데이터 구성
        Map<String, Object> responseData = new HashMap<>(transportResult.getBody());
        responseData.put("status", "SUCCESS");
        responseData.put("message", "인증이 완료되었습니다.");
        responseData.put("redirectUrl", determineTargetUrl(request, response, finalAuthentication));
        responseData.put("authentication", finalAuthentication);

        TokenTransportResult finalResult = TokenTransportResult.builder()
                .body(responseData)
                .cookiesToSet(transportResult.getCookiesToSet())
                .cookiesToRemove(transportResult.getCookiesToRemove())
                .headers(transportResult.getHeaders())
                .build();

        // 5. 위임 핸들러 호출
        if (delegateHandler != null && !response.isCommitted()) {
            try {
                delegateHandler.onAuthenticationSuccess(request, response, finalAuthentication, finalResult);
            } catch (Exception e) {
                log.error("Error in delegate handler", e);
            }
        }

        // 6. 하위 클래스 훅 호출
        if (!response.isCommitted()) {
            onFinalAuthenticationSuccess(request, response, finalAuthentication, finalResult);
        }

        // 7. 플랫폼 기본 응답
        if (!response.isCommitted()) {
            processDefaultResponse(response, finalResult);
        }
    }

    /**
     * 하위 클래스 확장점
     */
    protected void onFinalAuthenticationSuccess(HttpServletRequest request,
                                                HttpServletResponse response,
                                                Authentication authentication,
                                                TokenTransportResult transportResult) throws IOException {
        // 하위 클래스에서 필요시 오버라이드
    }

    private void processDefaultResponse(HttpServletResponse response, TokenTransportResult result)
            throws IOException {
        // 쿠키 설정
        if (result.getCookiesToSet() != null) {
            for (ResponseCookie cookie : result.getCookiesToSet()) {
                response.addHeader("Set-Cookie", cookie.toString());
            }
        }

        // JSON 응답
        responseWriter.writeSuccessResponse(response, result.getBody(), HttpServletResponse.SC_OK);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        SavedRequest savedRequest = this.requestCache.getRequest(request, response);
        if (savedRequest != null) {
            this.requestCache.removeRequest(request, response);
            return savedRequest.getRedirectUrl();
        }
        return request.getContextPath() + "/home";
    }
}