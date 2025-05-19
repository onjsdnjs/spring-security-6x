package io.springsecurity.springsecurity6x.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.domain.LoginRequest;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class RestAuthenticationFilter extends OncePerRequestFilter {

    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final RequestMatcher requestMatcher;
    private final ObjectMapper mapper = new ObjectMapper();

    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    private final AuthenticationManager authenticationManager;
    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;

    private final String mfaInitiateUrl;

    public RestAuthenticationFilter(AuthenticationManager authenticationManager,
                                    ContextPersistence contextPersistence,
                                    MfaPolicyProvider mfaPolicyProvider,
                                    RequestMatcher requestMatcher,
                                    String mfaInitiateUrl) { // mfaInitiateUrl 주입
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(contextPersistence, "contextPersistence cannot be null");
        Assert.notNull(mfaPolicyProvider, "mfaPolicyProvider cannot be null");
        Assert.notNull(requestMatcher, "requestMatcher cannot be null");
        Assert.hasText(mfaInitiateUrl, "mfaInitiateUrl cannot be empty");

        this.authenticationManager = authenticationManager;
        this.contextPersistence = contextPersistence;
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.requestMatcher = requestMatcher;
        this.mfaInitiateUrl = mfaInitiateUrl;

        this.successHandler = defaultSuccessHandler();
        this.failureHandler = defaultFailureHandler();
    }

    private AuthenticationSuccessHandler defaultSuccessHandler() {
        return (request, response, authentication) -> {
            log.info("DefaultSuccessHandler: Primary authentication successful for user: {}. No MFA required or MFA flow handled separately.", authentication.getName());
            // 실제 프로덕션에서는 JWT 토큰을 발급하거나, 적절한 성공 응답을 보내야 함.
            // 여기서는 간단한 JSON 응답으로 대체.
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String, Object> successResponse = new HashMap<>();
            successResponse.put("message", "Authentication successful.");
            successResponse.put("username", authentication.getName());
            // JWT 사용 시 여기에 토큰 정보 추가
            // successResponse.put("accessToken", "your_issued_access_token");
            // successResponse.put("refreshToken", "your_issued_refresh_token");
            mapper.writeValue(response.getWriter(), successResponse);
        };
    }

    // 기본 실패 핸들러
    private AuthenticationFailureHandler defaultFailureHandler() {
        return (request, response, exception) -> {
            log.warn("DefaultFailureHandler: Authentication failed: {}", exception.getMessage(), exception);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String, Object> errorResponse = Map.of(
                    "error", "Authentication Failed",
                    "message", exception.getMessage() != null ? exception.getMessage() : "Invalid credentials or authentication error."
            );
            mapper.writeValue(response.getWriter(), errorResponse);
        };
    }

    public void setSuccessHandler(AuthenticationSuccessHandler successHandler) {
        Assert.notNull(successHandler, "successHandler cannot be null");
        this.successHandler = successHandler;
    }

    public void setFailureHandler(AuthenticationFailureHandler failureHandler) {
        Assert.notNull(failureHandler, "failureHandler cannot be null");
        this.failureHandler = failureHandler;
    }

    public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
        Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        log.debug("RestAuthenticationFilter: Processing request for {}", request.getRequestURI());

        try {
            Authentication authResult = attemptAuthentication(request);
            successfulAuthentication(request, response, filterChain, authResult);
        } catch (AuthenticationException ex) {
            log.warn("RestAuthenticationFilter: Authentication attempt failed for {}: {}", request.getRequestURI(), ex.getMessage());
            unsuccessfulAuthentication(request, response, ex);
        }
    }

    protected Authentication attemptAuthentication(HttpServletRequest request)
            throws AuthenticationException, IOException {
        LoginRequest loginRequest;
        try {
            loginRequest = mapper.readValue(request.getInputStream(), LoginRequest.class);
        } catch (IOException e) {
            log.error("RestAuthenticationFilter: Failed to parse login request body.", e);
            throw new AuthenticationServiceException("Failed to parse login request body.", e);
        }

        if (loginRequest.username() == null || loginRequest.password() == null) {
            log.warn("RestAuthenticationFilter: Username or password not provided in login request.");
            throw new BadCredentialsException("Username and password must be provided.");
        }

        UsernamePasswordAuthenticationToken authRequest =
                UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(), loginRequest.password());
        authRequest.setDetails(new WebAuthenticationDetails(request)); // 요청 상세 정보 설정
        return this.authenticationManager.authenticate(authRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authentication) throws IOException, ServletException {
        log.info("RestAuthenticationFilter: Primary authentication successful for user: {}", authentication.getName());

        // SecurityContext에 인증 정보 저장 (세션 기반이거나, 후속 필터에서 필요시)
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response); // 중요: SecurityContextRepository 사용

        // 이전 MFA 세션 정보가 있다면 삭제 (새로운 1차 인증 성공이므로)
        contextPersistence.deleteContext(request);

        // FactorContext 생성 및 MFA 정책 평가 (MfaPolicyProvider를 통해)
        // 생성자에서 초기 상태는 PRIMARY_AUTHENTICATION_COMPLETED로 설정됨.
        FactorContext mfaCtx = new FactorContext(authentication);
        String deviceId = request.getHeader("X-Device-Id"); // 클라이언트에서 deviceId를 헤더로 보내준다고 가정
        if (deviceId != null) {
            mfaCtx.setAttribute("deviceId", deviceId); // FactorContext에 deviceId 저장
        }

        // MfaPolicyProvider가 mfaCtx의 mfaRequiredAsPerPolicy, registeredMfaFactors,
        // currentProcessingFactor (첫 번째 Factor), currentMfaState 등을 설정.
        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(authentication, mfaCtx);
        contextPersistence.saveContext(mfaCtx, request); // FactorContext 저장 (MFA 세션 시작)

        if (mfaCtx.isMfaRequiredAsPerPolicy()) {
            log.info("RestAuthenticationFilter: MFA is required for user: {}. Session ID: {}. Guiding to MFA initiation.",
                    authentication.getName(), mfaCtx.getMfaSessionId());

            // 클라이언트에게 MFA가 필요함을 알리고, 다음 단계를 안내하는 응답 전송
            // MfaCapableRestSuccessHandler가 이 역할을 하도록 위임하거나, 여기서 직접 응답 생성
            // PlatformSecurityConfig에서 RestAuthenticationFilter의 successHandler로
            // MfaCapableRestSuccessHandler 또는 PrimaryAuthenticationSuccessHandler를 지정.
            // 여기서는 해당 핸들러가 호출될 것을 기대하고, 직접 응답을 생성하지 않음.
            // Spring Security 필터 표준에 따라, 성공 시 successHandler 호출.
            this.successHandler.onAuthenticationSuccess(request, response, authentication);
            // successHandler (예: MfaCapableRestSuccessHandler)가 응답을 커밋할 것임.
        } else {
            log.info("RestAuthenticationFilter: MFA is not required for user: {}. Proceeding with final token issuance.", authentication.getName());
            // MFA가 필요 없는 경우, successHandler가 최종 토큰 발급 등의 로직을 수행.
            this.successHandler.onAuthenticationSuccess(request, response, authentication);
        }
    }

    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException exception) throws IOException, ServletException {
        securityContextHolderStrategy.clearContext();
        contextPersistence.deleteContext(request); // 실패 시에도 세션의 MFA 컨텍스트 정리
        this.failureHandler.onAuthenticationFailure(request, response, exception);
    }
}

