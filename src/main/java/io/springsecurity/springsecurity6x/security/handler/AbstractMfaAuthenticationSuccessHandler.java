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

@Slf4j
public abstract class AbstractMfaAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    protected final TokenService tokenService;
    protected final AuthResponseWriter responseWriter;
    protected final MfaSessionRepository sessionRepository;
    protected final MfaStateMachineIntegrator stateMachineIntegrator;
    protected final AuthContextProperties authContextProperties;
    private final RequestCache requestCache = new HttpSessionRequestCache();

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

    /**
     * 공통 최종 인증 성공 처리
     */
    protected void handleFinalAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                    Authentication finalAuthentication,
                                                    @Nullable FactorContext factorContext) throws IOException {
        log.info("All authentication steps completed for user: {}. Issuing final tokens using {} repository.",
                finalAuthentication.getName(), sessionRepository.getRepositoryType());

        String deviceIdFromCtx = factorContext != null ?
                (String) factorContext.getAttribute("deviceId") : null;

        String accessToken = tokenService.createAccessToken(finalAuthentication, deviceIdFromCtx);
        String refreshTokenVal = null;
        if (tokenService.properties().isEnableRefreshToken()) {
            refreshTokenVal = tokenService.createRefreshToken(finalAuthentication, deviceIdFromCtx);
        }

        // 세션 정리
        if (factorContext != null && factorContext.getMfaSessionId() != null) {
            stateMachineIntegrator.releaseStateMachine(factorContext.getMfaSessionId());
            sessionRepository.removeSession(factorContext.getMfaSessionId(), request, response);
        }

        TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshTokenVal);

        if (transportResult.getCookiesToSet() != null) {
            for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                response.addHeader("Set-Cookie", cookie.toString());
            }
        }

        String redirectUrl = determineTargetUrl(request, response, finalAuthentication);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", "SUCCESS");
        responseBody.put("message", "인증이 완료되었습니다.");
        responseBody.put("redirectUrl", redirectUrl);
        responseBody.put("accessToken", accessToken);
        if (refreshTokenVal != null) {
            responseBody.put("refreshToken", refreshTokenVal);
        }
        responseBody.put("repositoryType", sessionRepository.getRepositoryType());
        responseBody.put("distributedSync", sessionRepository.supportsDistributedSync());

        responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
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