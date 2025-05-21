package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.context.HttpSessionContextPersistence;
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

import java.util.Map;
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

        String tokenGeneratingUrl = authContextProperties.getMfa().getOttFactor().getCodeGenerationUrl(); // 기본값

        FactorContext ctx = (FactorContext) request.getSession().getAttribute(HttpSessionContextPersistence.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername())) {
            log.warn("MFA Select Factor UI: No valid FactorContext. Redirecting to login.");
            return "redirect:" + getContextPath(request) + "/loginForm?mfa_error=mfa_session_expired";
        }
        AuthenticationFlowConfig mfaFlowConfig = findFlowConfigByName(AuthType.MFA.name(), request);

        if (mfaFlowConfig != null) {
            // 현재 진행 중인 MFA OTT 스텝을 stepId로 찾음
            AuthenticationStepConfig currentOttStep = null;
            Optional<AuthenticationStepConfig> currentOttStepOpt = mfaFlowConfig.getStepConfigs().stream()
                    .filter(step -> ctx.getCurrentStepId().equals(step.getStepId()) && AuthType.OTT.name().equalsIgnoreCase(step.getType()))
                    .findFirst();

            if (currentOttStepOpt.isPresent()) {
                currentOttStep = currentOttStepOpt.get();
            }
            if (currentOttStep != null) {
                OttOptions ottOptions = getOttOptionsFromFlowOrFirstStep(currentOttStep);
                if (ottOptions != null && StringUtils.hasText(ottOptions.getTokenGeneratingUrl())) {
                    tokenGeneratingUrl = ottOptions.getTokenGeneratingUrl();
                }
            }
        }

        model.addAttribute("ottCodeRequestApiUrl", getContextPath(request) + tokenGeneratingUrl);
        return "login-ott";
    }

    // 코드 또는 매직링크 발송 완료 안내 페이지
    @GetMapping("/ott/sent")
    public String ottSentPage(@RequestParam String email,
                              @RequestParam(required = false) String type,
                              @RequestParam(required = false) String flow,
                              Model model, HttpServletRequest request) {
        model.addAttribute("email", email);
        model.addAttribute("pageTitle", "인증 메일 발송 완료");

        String nextChallengeUrl = null;
        String nextChallengeMessage = null;
        String contextPath = getContextPath(request);

        if ("code_sent".equals(type)) {
            model.addAttribute("messageType", "code_sent");
            if ("mfa".equalsIgnoreCase(flow)) {
                nextChallengeUrl = contextPath + authContextProperties.getMfa().getOttFactor().getChallengeUrl();
                nextChallengeMessage = "MFA 인증 코드 입력 페이지로 이동하여 코드를 입력해주세요.";
            } else { // 단일 OTT
                String singleOttVerifyPageUrl = "/loginOttVerifyCode"; // UI 경로
                nextChallengeUrl = UriComponentsBuilder.fromPath(contextPath + singleOttVerifyPageUrl)
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

        String processingUrl = authContextProperties.getMfa().getOttFactor().getLoginProcessingUrl(); // 기본값
        String resendUrl = authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl(); // 기본값

        FactorContext ctx = (FactorContext) request.getSession().getAttribute(HttpSessionContextPersistence.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername())) {
            log.warn("MFA Select Factor UI: No valid FactorContext. Redirecting to login.");
            return "redirect:" + getContextPath(request) + "/loginForm?mfa_error=mfa_session_expired";
        }
        AuthenticationFlowConfig mfaFlowConfig = findFlowConfigByName(AuthType.MFA.name(), request);

        if (mfaFlowConfig != null) {
            // 현재 진행 중인 MFA OTT 스텝을 stepId로 찾음
            AuthenticationStepConfig currentOttStep = null;
            Optional<AuthenticationStepConfig> currentOttStepOpt = mfaFlowConfig.getStepConfigs().stream()
                    .filter(step -> ctx.getCurrentStepId().equals(step.getStepId()) && AuthType.OTT.name().equalsIgnoreCase(step.getType()))
                    .findFirst();

            if (currentOttStepOpt.isPresent()) {
                currentOttStep = currentOttStepOpt.get();
            }
            if (currentOttStep != null) {
                OttOptions ottOptions = getOttOptionsFromFlowOrFirstStep(currentOttStep);
                if (ottOptions != null) {
                    if (StringUtils.hasText(ottOptions.getLoginProcessingUrl())) {
                        processingUrl = ottOptions.getLoginProcessingUrl();
                    }
                    if (StringUtils.hasText(ottOptions.getTokenGeneratingUrl())) {
                        resendUrl = ottOptions.getTokenGeneratingUrl();
                    }
                }
            }
        }

        model.addAttribute("ottProcessingUrl", getContextPath(request) + processingUrl);
        model.addAttribute("singleOttResendUrl", getContextPath(request) + resendUrl);
        model.addAttribute("isMfaFlow", false);

        if (StringUtils.hasText(error)) {
            model.addAttribute("errorMessage", "인증 코드가 잘못되었거나 만료되었습니다. 다시 시도해주세요.");
        }
        return "login-ott-verify-code";
    }

    @GetMapping("/loginPasskey")
    public String loginPasskeyPage(Model model, HttpServletRequest request) {
        model.addAttribute("pageTitle", "Passkey 로그인");
        String contextPath = getContextPath(request);
        model.addAttribute("passkeyAssertionOptionsUrl", contextPath + "/webauthn/assertion/options");
        model.addAttribute("passkeyAssertionProcessUrl", contextPath + "/login/webauthn");
        model.addAttribute("passkeyRegistrationOptionsUrl", contextPath + "/webauthn/registration/options");
        model.addAttribute("passkeyRegistrationProcessUrl", contextPath + "/webauthn/registration");
        return "login-passkey";
    }

    @GetMapping("/mfa/select-factor")
    public String mfaSelectFactorPage(Model model, HttpServletRequest request, @RequestParam(required = false) String error) {
        FactorContext ctx = (FactorContext) request.getSession().getAttribute(HttpSessionContextPersistence.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername())) {
            log.warn("MFA Select Factor UI: No valid FactorContext. Redirecting to login.");
            return "redirect:" + getContextPath(request) + "/loginForm?mfa_error=mfa_session_expired";
        }
        model.addAttribute("username", ctx.getUsername());
        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        if (StringUtils.hasText(error)) {
            model.addAttribute("errorMessage", "인증 수단 선택 중 오류: " + error);
        }
        model.addAttribute("pageTitle", "MFA 인증 수단 선택");
        return "login-mfa-select-factor";
    }

    @GetMapping("/mfa/ott/request-code-ui")
    public String mfaOttRequestCodeUiPage(Model model, HttpServletRequest request) {
        FactorContext ctx = (FactorContext) request.getSession().getAttribute(HttpSessionContextPersistence.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername()) || ctx.getCurrentProcessingFactor() != AuthType.OTT || !StringUtils.hasText(ctx.getCurrentStepId())) {
            log.warn("MFA OTT Request Code UI: Invalid FactorContext, not an OTT factor, or currentStepId is missing. Redirecting. Context: {}", ctx);
            return "redirect:" + getContextPath(request) + authContextProperties.getMfa().getSelectFactorUrl() + "?error=invalid_ott_request_context";
        }
        model.addAttribute("username", ctx.getUsername());
        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("pageTitle", "MFA - 이메일 인증 코드 요청");

        // MFA 플로우 설정을 가져옴
        AuthenticationFlowConfig mfaFlowConfig = findFlowConfigByName(AuthType.MFA.name(), request);
        String tokenGeneratingUrl = authContextProperties.getMfa().getOttFactor().getCodeGenerationUrl(); // 기본값

        if (mfaFlowConfig != null) {
            // 현재 진행 중인 MFA OTT 스텝을 stepId로 찾음
            Optional<AuthenticationStepConfig> currentOttStepOpt = mfaFlowConfig.getStepConfigs().stream()
                    .filter(step -> ctx.getCurrentStepId().equals(step.getStepId()) && AuthType.OTT.name().equalsIgnoreCase(step.getType()))
                    .findFirst();

            if (currentOttStepOpt.isPresent()) {
                AuthenticationStepConfig currentOttStep = currentOttStepOpt.get();
                // 해당 스텝의 OttOptions 에서 tokenGeneratingUrl을 가져옴
                // AuthenticationStepConfig에 getOptions()가 있고, 그 안에 OttOptions가 특정 키로 저장되어 있다고 가정.
                Object optionsObj = currentOttStep.getOptions().get("_options"); // 키는 실제 저장 방식에 따라 달라질 수 있음 (예: "_ottOptions")
                if (optionsObj instanceof OttOptions ottOptions) {
                    if (StringUtils.hasText(ottOptions.getTokenGeneratingUrl())) {
                        tokenGeneratingUrl = ottOptions.getTokenGeneratingUrl();
                        log.info("MFA OTT Request Code UI: Using tokenGeneratingUrl from MFA OTT Step (StepId: {}): {}", ctx.getCurrentStepId(), tokenGeneratingUrl);
                    } else {
                        log.warn("MFA OTT Request Code UI: tokenGeneratingUrl not found in OttOptions for MFA OTT Step (StepId: {}). Using default: {}", ctx.getCurrentStepId(), tokenGeneratingUrl);
                    }
                } else {
                    log.warn("MFA OTT Request Code UI: OttOptions not found or not of expected type for MFA OTT Step (StepId: {}). Using default: {}", ctx.getCurrentStepId(), tokenGeneratingUrl);
                }
            } else {
                log.warn("MFA OTT Request Code UI: Current MFA OTT Step (StepId: {}) not found in MFA flow. Using default: {}", ctx.getCurrentStepId(), tokenGeneratingUrl);
            }
        } else {
            log.warn("MFA OTT Request Code UI: MFA flow config not found. Using default tokenGeneratingUrl: {}", tokenGeneratingUrl);
        }

        model.addAttribute("mfaOttCodeRequestFormActionUrl", getContextPath(request) + tokenGeneratingUrl);
        return "login-mfa-ott-request-code";
    }

    @GetMapping("/mfa/challenge/ott")
    public String mfaVerifyOttPage(Model model, HttpServletRequest request, @RequestParam(value = "resend_success", required = false) String resendSuccess) {
        FactorContext ctx = (FactorContext) request.getSession().getAttribute(HttpSessionContextPersistence.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername()) || ctx.getCurrentProcessingFactor() != AuthType.OTT || !StringUtils.hasText(ctx.getCurrentStepId())) {
            log.warn("MFA OTT Challenge UI: Invalid FactorContext, not an OTT factor, or currentStepId is missing. Redirecting. Context: {}", ctx);
            return "redirect:" + getContextPath(request) + authContextProperties.getMfa().getSelectFactorUrl() + "?error=invalid_ott_challenge_context";
        }

        model.addAttribute("usernameForDisplay", ctx.getUsername());
        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("pageTitle", "MFA - 코드 입력");

        String loginProcessingUrl = authContextProperties.getMfa().getOttFactor().getChallengeUrl(); // 기본값
        AuthenticationFlowConfig mfaFlowConfig = findFlowConfigByName(AuthType.MFA.name(), request);

        if (mfaFlowConfig != null) {
            Optional<AuthenticationStepConfig> currentOttStepOpt = mfaFlowConfig.getStepConfigs().stream()
                    .filter(step -> ctx.getCurrentStepId().equals(step.getStepId()) && AuthType.OTT.name().equalsIgnoreCase(step.getType()))
                    .findFirst();

            if (currentOttStepOpt.isPresent()) {
                AuthenticationStepConfig currentOttStep = currentOttStepOpt.get();
                Object optionsObj = currentOttStep.getOptions().get("_options"); // 키는 실제 저장 방식에 따라 달라질 수 있음
                if (optionsObj instanceof OttOptions ottOptions && StringUtils.hasText(ottOptions.getLoginProcessingUrl())) {
                    loginProcessingUrl = ottOptions.getLoginProcessingUrl();
                    log.info("MFA OTT Challenge UI: Using loginProcessingUrl from MFA OTT Step (StepId: {}): {}", ctx.getCurrentStepId(), loginProcessingUrl);
                } else {
                    log.warn("MFA OTT Challenge UI: loginProcessingUrl not found in OttOptions for MFA OTT Step (StepId: {}). Using default: {}", ctx.getCurrentStepId(), loginProcessingUrl);
                }
            } else {
                log.warn("MFA OTT Challenge UI: Current MFA OTT Step (StepId: {}) not found in MFA flow. Using default loginProcessingUrl: {}", ctx.getCurrentStepId(), loginProcessingUrl);
            }
        } else {
            log.warn("MFA OTT Challenge UI: MFA flow config not found. Using default loginProcessingUrl: {}", loginProcessingUrl);
        }

        model.addAttribute("mfaOttProcessingUrl", getContextPath(request) + loginProcessingUrl);
        model.addAttribute("mfaResendOttUrl", getContextPath(request) + "/api/mfa/request-ott-code"); // MFA 코드 재전송 API

        if (resendSuccess != null) {
            model.addAttribute("successMessage", "인증 코드가 재전송되었습니다.");
        }
        String errorParam = request.getParameter("mfa_error");
        if (!StringUtils.hasText(errorParam)) {
            errorParam = request.getParameter("error"); // 일반 에러 파라미터도 확인
        }
        if (StringUtils.hasText(errorParam) && (model.getAttribute("errorMessage") == null || !StringUtils.hasText(String.valueOf(model.getAttribute("errorMessage"))))) {
            model.addAttribute("errorMessage", "인증 코드가 잘못되었거나 만료되었습니다.");
        }

        model.addAttribute("isMfaFlow", true);
        return "login-mfa-verify-code";
    }

    @GetMapping("/mfa/challenge/passkey")
    public String mfaVerifyPasskeyPage(Model model, HttpServletRequest request) {
        FactorContext ctx = (FactorContext) request.getSession().getAttribute(HttpSessionContextPersistence.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx == null || !StringUtils.hasText(ctx.getUsername()) || ctx.getCurrentProcessingFactor() != AuthType.PASSKEY) {
            log.warn("MFA Passkey Challenge UI: Invalid FactorContext or not a Passkey factor. Redirecting. Context: {}", ctx);
            return "redirect:" + getContextPath(request) + authContextProperties.getMfa().getSelectFactorUrl() + "?error=invalid_passkey_challenge_context";
        }
        model.addAttribute("usernameForDisplay", ctx.getUsername());
        model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
        model.addAttribute("pageTitle", "MFA - Passkey 인증");

        model.addAttribute("mfaPasskeyAssertionOptionsUrl", getContextPath(request) + "/api/mfa/assertion/options");
        String loginProcessingUrl = authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
        // MFA 플로우의 Passkey 단계 설정에서 loginProcessingUrl 가져오도록 개선 가능 (OTT와 유사하게)
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
                            String sessionId = (request != null && request.getSession(false) != null) ? request.getSession(false).getId() : "N/A";
                            log.warn("LoginController (Session: {}): No AuthenticationFlowConfig found with typeName: {}", sessionId, flowTypeName);
                            return null;
                        });
            }
        } catch (Exception e) {
            String sessionId = (request != null && request.getSession(false) != null) ? request.getSession(false).getId() : "N/A";
            log.warn("LoginController (Session: {}): Error finding flow config by name '{}': {}",sessionId, flowTypeName, e.getMessage());
        }
        return null;
    }

    /**
     * AuthenticationFlowConfig에서 OttOptions를 가져옵니다.
     * 플로우 자체의 옵션에 있거나, 첫 번째 스텝의 옵션에 있을 수 있습니다.
     * (IdentityDslRegistry가 단일 OTT 플로우를 어떻게 구성하는지에 따라 달라짐)
     */
    @Nullable
    private OttOptions getOttOptionsFromFlowOrFirstStep(AuthenticationStepConfig flowConfig) {
        if (flowConfig == null) return null;

        Map<String, Object> flowLevelOptionsMap = flowConfig.getOptions();
        if (flowLevelOptionsMap != null) {
            Object flowOttOptionsObj = flowLevelOptionsMap.get(OttOptions.class.getName()); // 키는 실제 저장 방식에 따라 다름
            if (flowOttOptionsObj instanceof OttOptions castedOptions) {
                return castedOptions;
            }
        }

        return null;
    }


    @GetMapping("/logout")
    public String logoutPage(Model model) {
        model.addAttribute("pageTitle", "로그아웃");
        return "logout";
    }
}