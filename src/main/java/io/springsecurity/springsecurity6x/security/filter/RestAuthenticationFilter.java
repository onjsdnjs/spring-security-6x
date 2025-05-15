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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType; // MediaType 추가
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException; // BadCredentialsException 추가
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.*; // HttpStatusEntryPoint, AuthenticationEntryPointFailureHandler 포함
import org.springframework.security.web.context.HttpSessionSecurityContextRepository; // 기본 SecurityContextRepository
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap; // HashMap 추가
import java.util.Map;

@Slf4j
public class RestAuthenticationFilter extends OncePerRequestFilter {

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final RequestMatcher requestMatcher;
    private final ObjectMapper mapper = new ObjectMapper();

    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    private final AuthenticationManager authenticationManager;
    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;

    // 전역 설정에서 주입받을 MFA 관련 URL (예시)
    private final String mfaInitiateUrl; // 예: "/mfa" 또는 "/mfa/initiate"

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

        // 기본 핸들러 설정
        this.successHandler = defaultSuccessHandler(); // MFA 불필요 시 사용될 핸들러
        this.failureHandler = defaultFailureHandler();
    }

    // 기본 성공 핸들러 (MFA가 필요 없는 경우 또는 토큰 기반 인증에서 토큰 발급 등)
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

    // setSecurityContextHolderStrategy는 보통 기본값을 사용하므로 Setter 생략 가능

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

    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authentication) throws IOException, ServletException {
        log.info("RestAuthenticationFilter: Primary authentication successful for user: {}", authentication.getName());

        // SecurityContext에 인증 정보 저장 (세션 기반이거나, 후속 필터에서 필요시)
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        // 이전 MFA 세션 정보가 있다면 삭제
        contextPersistence.deleteContext(request);

        // FactorContext 생성 및 MFA 정책 평가
        FactorContext mfaCtx = new FactorContext(authentication, Collections.emptyMap(), MfaState.PRIMARY_AUTHENTICATION_COMPLETED);
        mfaPolicyProvider.evaluateMfaPolicy(mfaCtx); // 이 메소드가 mfaCtx의 mfaRequired 등 필드를 설정

        if (mfaCtx.isMfaRequired()) {
            log.info("RestAuthenticationFilter: MFA is required for user: {}. Saving FactorContext.", authentication.getName());
            contextPersistence.saveContext(mfaCtx, request); // 생성된 MFA 컨텍스트를 세션에 저장

            // 클라이언트에게 MFA가 필요함을 알리고, 다음 단계를 안내하는 응답 전송
            response.setStatus(HttpServletResponse.SC_OK); // 1차 인증은 성공했으므로 200 OK
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String, Object> mfaRequiredResponse = new HashMap<>();
            mfaRequiredResponse.put("status", "MFA_REQUIRED");
            mfaRequiredResponse.put("message", "Primary authentication successful. MFA is required.");
            mfaRequiredResponse.put("mfaSessionId", mfaCtx.getMfaSessionId()); // 클라이언트가 다음 MFA 요청에 사용할 수 있도록 세션 ID 전달
            // 클라이언트가 다음 MFA 단계를 시작하기 위해 호출할 URL 또는 리다이렉트할 URL 제공
            mfaRequiredResponse.put("nextStepUrl", request.getContextPath() + this.mfaInitiateUrl); // 예: /mfa 또는 /mfa-challenge-page
            // mfaRequiredResponse.put("availableFactors", mfaCtx.getRegisteredMfaFactors()); // 사용 가능한 MFA 요소 정보 (선택적)

            mapper.writeValue(response.getWriter(), mfaRequiredResponse);
            // MFA 흐름이 시작되므로, 여기서 응답을 완료하고 필터 체인을 더 이상 진행하지 않음.
            return;
        } else {
            log.info("RestAuthenticationFilter: MFA is not required for user: {}. Proceeding with standard success handler.", authentication.getName());
            // MFA가 필요 없는 경우, 설정된 successHandler를 호출
            // (예: JWT 토큰 발급 및 응답, 또는 SavedRequestAwareAuthenticationSuccessHandler의 기본 동작)
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

