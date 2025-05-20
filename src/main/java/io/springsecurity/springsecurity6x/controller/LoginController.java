package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.context.SessionFactorContextManager;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
@Slf4j
public class LoginController {

    private final ApplicationContext applicationContext;
    private final AuthContextProperties authContextProperties;

    @GetMapping("/loginForm")
    public String loginForm(Model model, HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        String errorMessage = null;
        if (session != null) {
            Object exObject = session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
            if (exObject instanceof Exception ex) {
                errorMessage = ex.getMessage();
            } else if (exObject != null) {
                errorMessage = exObject.toString();
            }
            if (exObject != null) {
                session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
            }
        }
        if (request.getParameter("error") != null && errorMessage == null) {
            errorMessage = "로그인 정보가 정확하지 않거나 알 수 없는 오류가 발생했습니다.";
        }
        // MFA 관련 특정 에러 메시지 처리 (MfaContinuationFilter에서 리다이렉션 시 전달 가능)
        String mfaError = request.getParameter("mfa_error");
        if (StringUtils.hasText(mfaError)) {
            errorMessage = switch (mfaError) {
                case "mfa_session_missing_or_corrupted" -> "MFA 세션이 유효하지 않습니다. 다시 로그인해주세요.";
                case "mfa_session_already_ended" -> "MFA 세션이 이미 종료되었습니다. 다시 로그인해주세요.";
                case "invalid_mfa_init_context" -> "MFA 시작 컨텍스트가 유효하지 않습니다.";
                case "invalid_state_for_select_factor" -> "잘못된 상태에서 인증 수단 선택 페이지에 접근했습니다.";
                // MfaContinuationFilter의 handleInvalidContext, handleTerminalContext 등에서 설정한 에러 코드에 따라 추가
                default -> "MFA 처리 중 오류가 발생했습니다.";
            };
        }
        model.addAttribute("errorMessage", errorMessage);
        return "login-form";
    }

    // 단일 OTT: 이메일 입력 페이지
    @GetMapping("/loginOtt")
    public String loginOttPage(Model model, @RequestParam(value = "error", required = false) String error) {
        if (error != null) {
            model.addAttribute("errorMessage", "OTT 인증에 실패했습니다. 다시 시도해주세요.");
        }
        // 이 페이지의 폼은 /ott/generate (POST)로 제출되어 GenerateOneTimeTokenFilter가 처리
        return "login-ott";
    }

    // 단일/MFA OTT: 코드/링크 발송 완료 안내 페이지
    @GetMapping("/ott/sent")
    public String ottSentPage(@RequestParam String email,
                              @RequestParam(required = false) String type, // "code_sent" 또는 "magic_link_sent"
                              @RequestParam(required = false) String flow, // "single" 또는 "mfa"
                              Model model, HttpServletRequest request) {
        model.addAttribute("email", email);
        String contextPath = request.getContextPath();

        if ("code_sent".equals(type)) {
            model.addAttribute("messageType", "code_sent");
            if ("mfa".equals(flow)) {
                // MFA 코드 입력 페이지로 안내
                model.addAttribute("nextChallengeUrl", contextPath + authContextProperties.getOttFactor().getChallengeUrl());
                model.addAttribute("nextChallengeMessage", "MFA 코드 입력 페이지로 이동하여 코드를 입력해주세요.");
            } else {
                // 단일 OTT 코드 입력 페이지로 안내
                model.addAttribute("nextChallengeUrl", contextPath + "/loginOttVerifyCode?email=" + URLEncoder.encode(email, StandardCharsets.UTF_8));
                model.addAttribute("nextChallengeMessage", "코드 입력 페이지로 이동하여 코드를 입력해주세요.");
            }
        } else { // magic_link_sent 또는 기타
            model.addAttribute("messageType", "magic_link_sent");
            model.addAttribute("loginPageUrl", contextPath + authContextProperties.getOttFactor().getCodeSentUrl());
        }
        return "ott-sent";
    }

    // 단일 OTT 코드 입력 UI (신규)
    @GetMapping("/loginOttVerifyCode")
    public String loginOttVerifyCodePage(@RequestParam String email, Model model, HttpServletRequest request) {
        model.addAttribute("emailForVerification", email);
        // 이 페이지의 폼 action은 "/login/ott" (POST), OttAuthenticationAdapter에서 설정된 경로
        AuthenticationFlowConfig ottFlowConfig = findFlowConfigByName(AuthType.OTT.name().toLowerCase() + "_flow", request);
        String processingUrl = authContextProperties.getOttFactor().getCodeSentUrl(); // 기본값
        if (ottFlowConfig != null && !ottFlowConfig.getStepConfigs().isEmpty()) {
            Object options = ottFlowConfig.getStepConfigs().get(0).getOptions().get("_options");
            if (options instanceof io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions ottOpts) {
                if (StringUtils.hasText(ottOpts.getLoginProcessingUrl())) {
                    processingUrl = ottOpts.getLoginProcessingUrl();
                }
            }
        }
        model.addAttribute("ottProcessingUrl", request.getContextPath() + processingUrl);
        return "login-ott-verify-code"; // Thymeleaf 템플릿 (이전 답변의 내용 사용)
    }

    @GetMapping("/loginPasskey")
    public String loginPasskeyPage() {
        return "login-passkey";
    }

    // --- MFA 화면 매핑 ---
    @GetMapping("/mfa/select-factor")
    public String mfaSelectFactorPage(Model model, HttpServletRequest request, @RequestParam(required = false) String error) {
        FactorContext ctx = (FactorContext) request.getSession().getAttribute(SessionFactorContextManager.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername())) {
            log.warn("MFA Select Factor UI: No valid FactorContext. Redirecting to login.");
            return "redirect:" + request.getContextPath() + "/loginForm?error=mfa_session_expired";
        }
        model.addAttribute("username", ctx.getUsername());
        if (StringUtils.hasText(error)) {
            model.addAttribute("errorMessage", error); // MfaContinuationFilter에서 전달된 에러 메시지
        }
        // 이 페이지의 각 Factor 선택 버튼은 MfaContinuationFilter가 처리하는 GET URL로 연결
        // 예: <a th:href="@{/mfa/initiate-challenge(factor='OTT')}">OTT 인증</a>
        return "login-mfa-select-factor";
    }

    // MFA OTT 코드 "생성 요청" UI (MfaContinuationFilter가 이 페이지로 안내할 경우)
    // 이 페이지의 폼은 GenerateOneTimeTokenFilter가 처리하는 경로로 POST
    @GetMapping("/mfa/ott/request-code-ui")
    public String mfaOttRequestCodeUiPage(Model model, HttpServletRequest request) {
        FactorContext ctx = (FactorContext) request.getSession().getAttribute(SessionFactorContextManager.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername()) || ctx.getCurrentProcessingFactor() != AuthType.OTT) {
            log.warn("MFA OTT Request Code UI: Invalid FactorContext or not an OTT factor. Redirecting. Context: {}", ctx);
            return "redirect:" + request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl() + "?error=invalid_ott_request_context";
        }
        model.addAttribute("username", ctx.getUsername());
        // 폼 action은 PlatformSecurityConfig DSL의 MFA OTT Factor tokenGeneratingUrl (예: /mfa/ott/generate)
        AuthenticationFlowConfig mfaFlowConfig = findFlowConfigByName(AuthType.MFA.name().toLowerCase(), request);
        String tokenGeneratingUrl = authContextProperties.getOttFactor().getCodeGenerationUrl(); // 기본값
        if (mfaFlowConfig != null) {
            Optional<OttOptions> ottOpts = mfaFlowConfig.getStepConfigs().stream()
                    .filter(step -> AuthType.OTT.name().equalsIgnoreCase(step.getType()))
                    .map(step -> step.getOptions().get("_options"))
                    .filter(OttOptions.class::isInstance).map(OttOptions.class::cast)
                    .findFirst();
            if (ottOpts.isPresent() && StringUtils.hasText(ottOpts.get().getTokenGeneratingUrl())) {
                tokenGeneratingUrl = ottOpts.get().getTokenGeneratingUrl();
            }
        }
        model.addAttribute("mfaOttTokenGeneratingUrl", request.getContextPath() + tokenGeneratingUrl);
        return "login-mfa-ott-request-code";
    }

    // MFA OTT 코드 "입력" UI
    @GetMapping("/mfa/challenge/ott")
    public String mfaVerifyOttPage(Model model, HttpServletRequest request, @RequestParam(value = "resend_success", required = false) String resendSuccess) {
        /*FactorContext ctx = (FactorContext) request.getSession().getAttribute(SessionFactorContextManager.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername()) || ctx.getCurrentProcessingFactor() != AuthType.OTT) {
            log.warn("MFA OTT Challenge UI: Invalid FactorContext or not an OTT factor. Redirecting. Context: {}", ctx);
            return "redirect:" + request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl() + "?error=invalid_ott_challenge_context";
        }
        model.addAttribute("usernameForDisplay", ctx.getUsername());
        // 폼 action은 PlatformSecurityConfig DSL의 MFA OTT Factor loginProcessingUrl (예: /login/mfa-ott)
        AuthenticationFlowConfig mfaFlowConfig = findFlowConfigByName(AuthType.MFA.name().toLowerCase(), request);
        String loginProcessingUrl = authContextProperties.getOttFactor().getChallengeUrl(); // 프로퍼티에서는 이게 loginProcessingUrl 역할
        if (mfaFlowConfig != null) {
            Optional<OttOptions> ottOpts = mfaFlowConfig.getStepConfigs().stream()
                    .filter(step -> AuthType.OTT.name().equalsIgnoreCase(step.getType()) && Objects.equals(step.getStepId(), ctx.getCurrentStepId()))
                    .map(step -> step.getOptions().get("_options"))
                    .filter(OttOptions.class::isInstance).map(OttOptions.class::cast)
                    .findFirst();
            if (ottOpts.isPresent() && StringUtils.hasText(ottOpts.get().getLoginProcessingUrl())) {
                loginProcessingUrl = ottOpts.get().getLoginProcessingUrl();
            }
        }
        model.addAttribute("mfaOttProcessingUrl", request.getContextPath() + loginProcessingUrl);
        model.addAttribute("mfaResendOttUrl", request.getContextPath() + authContextProperties.getMfa().getInitiateUrl() + "/resend-ott"); // 재전송 URL
        if (resendSuccess != null) {
            model.addAttribute("successMessage", "인증 코드가 재전송되었습니다.");
        }*/
//        return "login-mfa-verify-ott";
        return "login-ott-verify-code";
    }

    // MFA Passkey 챌린지 UI
    /*@GetMapping("/mfa/challenge/passkey")
    public String mfaVerifyPasskeyPage(Model model, HttpServletRequest request) {
        FactorContext ctx = (FactorContext) request.getSession().getAttribute(SessionFactorContextManager.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername()) || ctx.getCurrentProcessingFactor() != AuthType.PASSKEY) {
            log.warn("MFA Passkey Challenge UI: Invalid FactorContext or not a Passkey factor. Redirecting. Context: {}", ctx);
            return "redirect:" + request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl() + "?error=invalid_passkey_challenge_context";
        }
        model.addAttribute("username", ctx.getUsername()); // JS에서 사용
        // JS는 DSL에 정의된 Passkey Factor의 assertionOptionsEndpoint로 AJAX 요청 후,
        // loginProcessingUrl (예: /login/mfa-passkey - POST)로 결과를 제출.
        // 관련 URL들을 모델에 담아 전달.
        AuthenticationFlowConfig mfaFlowConfig = findFlowConfigByName(AuthType.MFA.name().toLowerCase(), request);
        String assertionOptionsUrl = authContextProperties.getPasskeyFactor().getAssertionOptionsEndpoint();
        String loginProcessingUrl = authContextProperties.getPasskeyFactor().getLoginProcessingUrl(); // 프로퍼티의 challengeUrl이 아님

        if (mfaFlowConfig != null) {
            Optional<io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions> pkOpts = mfaFlowConfig.getStepConfigs().stream()
                    .filter(step -> AuthType.PASSKEY.name().equalsIgnoreCase(step.getType()) && Objects.equals(step.getStepId(), ctx.getCurrentStepId()))
                    .map(step -> step.getOptions().get("_options"))
                    .filter(io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions.class::isInstance)
                    .map(io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions.class::cast)
                    .findFirst();
            if (pkOpts.isPresent()) {
                if (StringUtils.hasText(pkOpts.get().getAssertionOptionsEndpoint())) assertionOptionsUrl = pkOpts.get().getAssertionOptionsEndpoint();
                if (StringUtils.hasText(pkOpts.get().getLoginProcessingUrl())) loginProcessingUrl = pkOpts.get().getLoginProcessingUrl();
            }
        }
        model.addAttribute("mfaPasskeyAssertionOptionsUrl", request.getContextPath() + assertionOptionsUrl);
        model.addAttribute("mfaPasskeyProcessingUrl", request.getContextPath() + loginProcessingUrl);
        return "login-mfa-verify-passkey";
    }*/

    @GetMapping("/mfa/failure")
    public String mfaFailurePage(@RequestParam(required = false) String error, Model model) {
        String errorMessage = "MFA 인증에 실패했습니다. 다시 시도해주세요.";
        if (StringUtils.hasText(error)) {
            // MfaContinuationFilter 또는 다른 핸들러에서 전달된 구체적인 오류 메시지 사용 가능
            errorMessage = error; // 이미 URL 디코딩된 상태로 넘어옴
        }
        model.addAttribute("errorMessage", errorMessage);
        return "mfa-failure";
    }

    // 나머지 GET 매핑 (예: /home, /users, /admin, /logout UI 페이지)들은 기존과 유사하게 유지

    @Nullable
    private AuthenticationFlowConfig findFlowConfigByName(String flowTypeName, HttpServletRequest request) {
        if (!StringUtils.hasText(flowTypeName)) return null;
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig != null && platformConfig.getFlows() != null) {
                return platformConfig.getFlows().stream()
                        .filter(flow -> flowTypeName.equalsIgnoreCase(flow.getTypeName()))
                        .findFirst()
                        .orElseGet(() -> {
                            log.warn("LoginController: No AuthenticationFlowConfig found with typeName: {}", flowTypeName);
                            return null;
                        });
            }
        } catch (Exception e) { log.warn("LoginController: Error finding flow config by name '{}': {}", flowTypeName, e.getMessage()); }
        return null;
    }


    @GetMapping("/logout") // GET 요청으로 로그아웃 페이지를 보여주고, JS가 POST /api/auth/logout 호출
    public String logoutPage() {
        return "logout";
    }
}

