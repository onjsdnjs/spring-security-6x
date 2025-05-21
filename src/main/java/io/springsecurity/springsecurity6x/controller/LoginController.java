package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
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
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Optional;

@Controller
@RequiredArgsConstructor
@Slf4j
public class LoginController {

    private final ApplicationContext applicationContext;
    private final AuthContextProperties authContextProperties;

    private String getContextPath(HttpServletRequest request) {
        return request.getContextPath();
    }

    @GetMapping("/loginForm")
    public String loginForm(Model model, HttpServletRequest request, @RequestParam(value = "error", required = false) String errorParam, @RequestParam(value = "logout", required = false) String logoutParam) {
        HttpSession session = request.getSession(false);
        String errorMessage = null;
        String infoMessage = null;

        if (session != null) {
            Object exObject = session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
            if (exObject instanceof Exception ex) {
                errorMessage = ex.getMessage();
                session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
            } else if (exObject != null && !(exObject instanceof String && ((String) exObject).isEmpty())) { // 빈 문자열 에러는 무시
                errorMessage = exObject.toString();
                session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
            }
        }

        if (StringUtils.hasText(errorParam) && errorMessage == null) {
            errorMessage = "사용자 이름 또는 비밀번호가 잘못되었습니다.";
        }

        String mfaError = request.getParameter("mfa_error");
        if (StringUtils.hasText(mfaError)) {
            errorMessage = switch (mfaError) {
                case "mfa_session_missing_or_corrupted", "mfa_session_expired" -> "MFA 세션이 유효하지 않거나 만료되었습니다. 다시 로그인해주세요.";
                case "mfa_session_already_ended" -> "MFA 세션이 이미 종료되었습니다. 다시 로그인해주세요.";
                case "invalid_mfa_init_context" -> "MFA 시작 컨텍스트가 유효하지 않습니다.";
                case "invalid_state_for_select_factor" -> "잘못된 상태에서 인증 수단 선택 페이지에 접근했습니다.";
                case "invalid_ott_request_context" -> "잘못된 OTT 코드 요청 컨텍스트입니다. 인증을 다시 시작해주세요.";
                case "invalid_ott_challenge_context" -> "잘못된 OTT 코드 입력 컨텍스트입니다. 인증을 다시 시작해주세요.";
                case "invalid_passkey_challenge_context" -> "잘못된 Passkey 인증 요청입니다. 인증을 다시 시작해주세요.";
                case "factor_config_error_request_ui", "factor_config_error_challenge_ui" -> "인증 수단 설정에 오류가 있습니다. 관리자에게 문의하세요.";
                case "invalid_challenge_page_url" -> "잘못된 인증 페이지 요청입니다.";
                case "invalid_state_for_mfa_page" -> "잘못된 상태에서 접근했습니다. 다시 로그인해주세요.";
                default -> "MFA 처리 중 오류가 발생했습니다: " + mfaError;
            };
        }

        String messageParam = request.getParameter("message");
        if (StringUtils.hasText(messageParam) && errorMessage == null && infoMessage == null) {
            switch (messageParam) {
                case "ott_setup_issue", "ott_setup_error":
                    errorMessage = "OTT 설정에 문제가 발생했습니다. 관리자에게 문의하세요.";
                    break;
                case "ott_generation_success_unknown_flow":
                    errorMessage = "OTT 코드 생성 후 알 수 없는 흐름으로 진행되었습니다.";
                    break;
                case "logout_success":
                    infoMessage = "성공적으로 로그아웃되었습니다.";
                    break;
                default:
                    infoMessage = messageParam;
            }
        }
        if (logoutParam != null && infoMessage == null) {
            infoMessage = "성공적으로 로그아웃되었습니다.";
        }

        model.addAttribute("errorMessage", errorMessage);
        model.addAttribute("infoMessage", infoMessage);
        model.addAttribute("pageTitle", "로그인");
        return "login-form";
    }

    // 단일 OTT 이메일 입력 페이지
    @GetMapping("/loginOtt")
    public String loginOttPage(Model model, HttpServletRequest request, @RequestParam(value = "error", required = false) String error) {
        if (error != null) {
            model.addAttribute("errorMessage", "이메일 인증 코드 요청에 실패했습니다. 다시 시도해주세요.");
        }
        model.addAttribute("pageTitle", "OTT 이메일 입력");
        // 단일 OTT 코드 생성은 /api/ott/generate-code (POST) API 호출을 사용.
        model.addAttribute("ottCodeRequestApiUrl", getContextPath(request) + "/api/ott/generate-code");
        return "login-ott"; // templates/login-ott.html
    }

    // 코드 또는 매직링크 발송 완료 안내 페이지
    @GetMapping("/ott/sent")
    public String ottSentPage(@RequestParam String email,
                              @RequestParam(required = false) String type, // "code_sent" or "magic_link_sent"
                              @RequestParam(required = false) String flow, // "mfa" or "ott_single"
                              Model model, HttpServletRequest request) {
        model.addAttribute("email", email);
        model.addAttribute("pageTitle", "인증 메일 발송 완료");

        String nextChallengeUrl = null;
        String nextChallengeMessage = null;
        String contextPath = getContextPath(request);

        if ("code_sent".equals(type)) {
            model.addAttribute("messageType", "code_sent");
            if ("mfa".equalsIgnoreCase(flow)) {
                // MFA OTT 코드 입력 페이지 URL (DSL에서 설정된 ottFactor.challengeUrl 사용)
                nextChallengeUrl = contextPath + authContextProperties.getMfa().getOttFactor().getChallengeUrl(); // 예: /mfa/challenge/ott
                nextChallengeMessage = "MFA 인증 코드 입력 페이지로 이동하여 코드를 입력해주세요.";
            } else { // 단일 OTT (flow가 "ott_single" 또는 명시되지 않은 경우)
                // 단일 OTT 코드 입력 페이지 URL. properties의 ottFactor.challengeUrl은 MFA용일 수 있으므로 주의.
                // PlatformSecurityConfig에서 단일 OTT용 loginProcessingUrl을 확인해야 함.
                // 여기서는 /loginOttVerifyCode?email=... 형태로 가정
                String singleOttVerifyUrl = authContextProperties.getMfa().getOttFactor().getChallengeUrl(); // 이 값은 /login/ott/verify 등이 되어야 함.
                // LoginController의 loginOttVerifyCodePage 매핑 경로와 일치해야함
                if(!singleOttVerifyUrl.contains("loginOttVerifyCode")) { // 임시 방편
                    singleOttVerifyUrl = "/loginOttVerifyCode";
                }
                nextChallengeUrl = UriComponentsBuilder.fromPath(contextPath + singleOttVerifyUrl)
                        .queryParam("email", email)
                        .toUriString();
                nextChallengeMessage = "인증 코드 입력 페이지로 이동하여 코드를 입력해주세요.";
            }
            model.addAttribute("nextChallengeMessage", nextChallengeMessage);
            model.addAttribute("nextChallengeUrl", nextChallengeUrl);
        } else if ("magic_link_sent".equals(type)) {
            model.addAttribute("messageType", "magic_link_sent");
            model.addAttribute("loginPageUrl", contextPath + "/loginForm");
        } else {
            model.addAttribute("messageType", "unknown_sent_type");
            model.addAttribute("nextChallengeMessage", "이메일을 확인해주세요.");
        }
        return "ott-sent";
    }

    // 단일 OTT 코드 입력 및 검증 페이지
    @GetMapping("/loginOttVerifyCode")
    public String loginOttVerifyCodePage(@RequestParam String email, Model model, HttpServletRequest request, @RequestParam(required = false) String error) {
        model.addAttribute("emailForVerification", email);
        model.addAttribute("pageTitle", "OTT 코드 검증");

        // 단일 OTT 검증 처리 URL (PlatformSecurityConfig의 ott() DSL에서 loginProcessingUrl로 설정된 값)
        String processingUrl = authContextProperties.getMfa().getOttFactor().getChallengeUrl(); // 이 값은 /login/ott/verify 와 같아야 함.
        AuthenticationFlowConfig ottFlowConfig = findFlowConfigByName(AuthType.OTT.name().toLowerCase() + "_flow", request);
        if (ottFlowConfig != null && !ottFlowConfig.getStepConfigs().isEmpty()) {
            AuthenticationStepConfig stepConfig = ottFlowConfig.getStepConfigs().get(0);
            if (stepConfig.getOptions().get("_options") instanceof OttOptions ottOpts) {
                if (StringUtils.hasText(ottOpts.getLoginProcessingUrl())) {
                    processingUrl = ottOpts.getLoginProcessingUrl();
                }
            }
        }
        model.addAttribute("ottProcessingUrl", getContextPath(request) + processingUrl);
        model.addAttribute("isMfaFlow", false); // 단일 OTT 플로우
        if (StringUtils.hasText(error)) {
            model.addAttribute("errorMessage", "인증 코드가 잘못되었거나 만료되었습니다. 다시 시도해주세요.");
        }
        // 단일 OTT 재전송 API URL
        model.addAttribute("singleOttResendUrl", getContextPath(request) + "/api/ott/generate-code");
        return "login-ott-verify-code";
    }

    @GetMapping("/loginPasskey")
    public String loginPasskeyPage(Model model, HttpServletRequest request) {
        model.addAttribute("pageTitle", "Passkey 로그인");
        String contextPath = getContextPath(request);
        // 단일 Passkey 인증 관련 URL들
        model.addAttribute("passkeyAssertionOptionsUrl", contextPath + "/webauthn/assertion/options"); // Spring Security WebAuthn 기본값 또는 DSL 설정값
        model.addAttribute("passkeyAssertionProcessUrl", contextPath + "/login/webauthn");      // Spring Security WebAuthn 기본값 또는 DSL 설정값
        model.addAttribute("passkeyRegistrationOptionsUrl", contextPath + "/webauthn/registration/options"); // Spring Security WebAuthn 기본값 또는 DSL 설정값
        model.addAttribute("passkeyRegistrationProcessUrl", contextPath + "/webauthn/registration");   // Spring Security WebAuthn 기본값 또는 DSL 설정값
        return "login-passkey";
    }

    @GetMapping("/mfa/select-factor")
    public String mfaSelectFactorPage(Model model, HttpServletRequest request, @RequestParam(required = false) String error) {
        FactorContext ctx = (FactorContext) request.getSession().getAttribute(SessionFactorContextManager.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername())) {
            log.warn("MFA Select Factor UI: No valid FactorContext. Redirecting to login.");
            return "redirect:" + getContextPath(request) + "/loginForm?mfa_error=mfa_session_expired";
        }
        model.addAttribute("username", ctx.getUsername());
        model.addAttribute("mfaSessionId", ctx.getMfaSessionId()); // JS에서 API 호출 시 필요
        if (StringUtils.hasText(error)) {
            model.addAttribute("errorMessage", "인증 수단 선택 중 오류: " + error);
        }
        model.addAttribute("pageTitle", "MFA 인증 수단 선택");
        return "login-mfa-select-factor";
    }

    @GetMapping("/mfa/ott/request-code-ui")
    public String mfaOttRequestCodeUiPage(Model model, HttpServletRequest request) {
        FactorContext ctx = (FactorContext) request.getSession().getAttribute(SessionFactorContextManager.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername()) || ctx.getCurrentProcessingFactor() != AuthType.OTT) {
            log.warn("MFA OTT Request Code UI: Invalid FactorContext or not an OTT factor. Redirecting. Context: {}", ctx);
            return "redirect:" + getContextPath(request) + authContextProperties.getMfa().getSelectFactorUrl() + "?error=invalid_ott_request_context";
        }
        model.addAttribute("username", ctx.getUsername());
        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("pageTitle", "MFA - 이메일 인증 코드 요청");
        // JavaScript에서 사용할 API URL
        model.addAttribute("mfaOttCodeRequestApiUrl", getContextPath(request) + "/api/mfa/request-ott-code");
        return "login-mfa-ott-request-code";
    }

    @GetMapping("/mfa/challenge/ott")
    public String mfaVerifyOttPage(Model model, HttpServletRequest request, @RequestParam(value = "resend_success", required = false) String resendSuccess) {
        /*FactorContext ctx = (FactorContext) request.getSession().getAttribute(SessionFactorContextManager.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername()) || ctx.getCurrentProcessingFactor() != AuthType.OTT) {
            log.warn("MFA OTT Challenge UI: Invalid FactorContext or not an OTT factor. Redirecting. Context: {}", ctx);
            return "redirect:" + getContextPath(request) + authContextProperties.getMfa().getSelectFactorUrl() + "?error=invalid_ott_challenge_context";
        }

        model.addAttribute("usernameForDisplay", ctx.getUsername());
        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("pageTitle", "MFA - 코드 입력");

        AuthenticationFlowConfig mfaFlowConfig = findFlowConfigByName(AuthType.MFA.name().toLowerCase(), request);
        String loginProcessingUrl = null; // MFA OTT 검증을 처리할 URL

        if (mfaFlowConfig != null && StringUtils.hasText(ctx.getCurrentStepId())) {
            Optional<AuthenticationStepConfig> currentStepOpt = mfaFlowConfig.getStepConfigs().stream()
                    .filter(step -> ctx.getCurrentStepId().equals(step.getStepId()) && AuthType.OTT.name().equalsIgnoreCase(step.getType()))
                    .findFirst();

            if (currentStepOpt.isPresent()) {
                Object options = currentStepOpt.get().getOptions().get("_options");
                if (options instanceof OttOptions ottOpts && StringUtils.hasText(ottOpts.getLoginProcessingUrl())) {
                    loginProcessingUrl = ottOpts.getLoginProcessingUrl(); // DSL에서 설정된 값
                }
            }
        }

        if (!StringUtils.hasText(loginProcessingUrl)) {
            // DSL 설정이 없다면 properties의 값을 사용 (이 값은 실제 검증 필터 URL이어야 함)
            loginProcessingUrl = authContextProperties.getOttFactor().getChallengeUrl();
            log.warn("MFA OTT loginProcessingUrl not found from DSL for stepId: {}. Using properties value: {}", ctx.getCurrentStepId(), loginProcessingUrl);
            // 안전장치: properties의 challengeUrl이 UI 경로와 동일하다면, 실제 검증 경로는 다를 수 있으므로 주의
            if (!loginProcessingUrl.startsWith("/login/mfa")) { // 일반적으로 MFA 검증은 /login/mfa/* 패턴
                loginProcessingUrl = "/login/mfa-ott"; // 가장 일반적인 기본값
                log.warn("MFA OTT loginProcessingUrl from properties seems like a UI path. Defaulting to {}", loginProcessingUrl);
            }
        }
        model.addAttribute("mfaOttProcessingUrl", getContextPath(request) + loginProcessingUrl);
        model.addAttribute("mfaResendOttUrl", getContextPath(request) + "/api/mfa/request-ott-code"); // 코드 재전송 API

        if (resendSuccess != null) {
            model.addAttribute("successMessage", "인증 코드가 재전송되었습니다.");
        }
        if (request.getParameter("error") != null && !StringUtils.hasText(model.getAttribute("errorMessage").toString())) {
            model.addAttribute("errorMessage", "인증 코드가 잘못되었거나 만료되었습니다.");
        }

        model.addAttribute("isMfaFlow", true); // 템플릿에서 MFA 흐름 구분용*/
        return "login-mfa-ott-request-code";
    }

    @GetMapping("/mfa/challenge/passkey")
    public String mfaVerifyPasskeyPage(Model model, HttpServletRequest request) {
        FactorContext ctx = (FactorContext) request.getSession().getAttribute(SessionFactorContextManager.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername()) || ctx.getCurrentProcessingFactor() != AuthType.PASSKEY) {
            log.warn("MFA Passkey Challenge UI: Invalid FactorContext or not a Passkey factor. Redirecting. Context: {}", ctx);
            return "redirect:" + getContextPath(request) + authContextProperties.getMfa().getSelectFactorUrl() + "?error=invalid_passkey_challenge_context";
        }
        model.addAttribute("usernameForDisplay", ctx.getUsername());
        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("pageTitle", "MFA - Passkey 인증");

        // Passkey Assertion Options 요청 API URL
        model.addAttribute("mfaPasskeyAssertionOptionsUrl", getContextPath(request) + "/api/mfa/assertion/options");
        // Passkey Assertion 검증 처리 URL (MfaStepFilterWrapper가 처리)
        String loginProcessingUrl = authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl(); // DSL에서 설정된 값 사용
        model.addAttribute("mfaPasskeyProcessingUrl", getContextPath(request) + loginProcessingUrl);

        return "login-mfa-verify-passkey";
    }


    @GetMapping("/mfa/failure")
    public String mfaFailurePage(@RequestParam(required = false) String error, @RequestParam(required = false) String message, Model model) {
        String errorMessageToDisplay = "MFA 인증에 실패했습니다. 다시 시도해주세요.";
        if (StringUtils.hasText(message)) {
            errorMessageToDisplay = message;
        } else if (StringUtils.hasText(error)) {
            errorMessageToDisplay = switch (error) {
                case "mfa_max_attempts_exceeded_ott" -> "OTT 인증 최대 시도 횟수를 초과했습니다. 잠시 후 다시 시도해주세요.";
                case "mfa_locked_ott" -> "OTT 인증이 잠겼습니다. 관리자에게 문의하세요.";
                case "mfa_factor_verification_failed" -> "제공된 인증 정보가 올바르지 않습니다.";
                default -> "MFA 인증 중 오류 발생: " + error;
            };
        }
        model.addAttribute("errorMessage", errorMessageToDisplay);
        model.addAttribute("pageTitle", "MFA 인증 실패");
        return "mfa-failure";
    }

    @Nullable
    private AuthenticationFlowConfig findFlowConfigByName(String flowTypeName, @Nullable HttpServletRequest request) {
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
        } catch (Exception e) {
            log.warn("LoginController: Error finding flow config by name '{}': {}", flowTypeName, e.getMessage());
        }
        return null;
    }

    @GetMapping("/logout")
    public String logoutPage(Model model) {
        model.addAttribute("pageTitle", "로그아웃");
        return "logout";
    }
}