package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.context.SessionFactorContextManager;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.service.ott.CodeStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Comparator;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
@Slf4j
public class LoginController {

    private final CodeStore codeStore; // 단일 OTT 로그인 시 사용

    // --- 기존 단일 인증 화면 매핑 ---
    @GetMapping("/loginForm")
    public String loginForm(Model model, HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        String errorMessage = null;
        if (session != null) {
            Exception ex = (Exception) session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
            if (ex != null) {
                errorMessage = ex.getMessage(); // 실제로는 더 구체적인 오류 메시지 처리
                session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION); // 오류 메시지 소비
            }
        }
        model.addAttribute("errorMessage", errorMessage);
        return "login-form";
    }

    @GetMapping("/loginOtt")
    public String loginOttPage() { // 단일 OTT 로그인 요청 페이지
        return "login-ott";
    }

    // 단일 OTT 인증: 이메일 링크 클릭 시 토큰과 함께 이리로 와서 자동 로그인 시도
    /*@GetMapping("/login/ott")
    public String loginOttByCode(@RequestParam String code, Model model) {
        OneTimeToken ott = codeStore.consume(code);
        if (ott == null) {
            model.addAttribute("errorMessage", "유효하지 않거나 만료된 인증 링크입니다.");
            return "login-ott"; // 오류 메시지와 함께 OTT 요청 페이지로
        }
        model.addAttribute("username", ott.getUsername());
        model.addAttribute("token", ott.getTokenValue());
        return "ott-forward"; // JS가 자동 POST하여 로그인 시도
    }*/

    @GetMapping("/ott/sent")
    public String ottSentPage(@RequestParam String email, Model model) {
        model.addAttribute("email", email);
        return "ott-sent";
    }

    @GetMapping("/loginPasskey")
    public String loginPasskeyPage() { // 단일 Passkey 로그인 페이지
        return "login-passkey";
    }

    // --- MFA 화면 매핑 ---
    @GetMapping("/mfa/select-factor")
    public String mfaSelectFactorPage(Model model, HttpSession session) {
        // MFA 세션에서 사용자 정보나 사용 가능한 factor 목록을 가져와 모델에 추가 가능
        // String username = (String) session.getAttribute("mfaUsername"); // 예시
        // List<String> availableFactors = (List<String>) session.getAttribute("availableMfaFactors"); // 예시
        // model.addAttribute("username", username);
        // model.addAttribute("availableFactors", availableFactors);
        // 현재는 JS에서 sessionStorage를 사용하므로, 서버에서 직접 모델에 담을 필요는 없을 수 있음.
        // 단, 서버 주도 흐름이라면 여기서 모델에 데이터를 담아 전달.
        return "login-mfa-select-factor";
    }

    // MFA 플로우용 OTT 코드 생성 요청 UI
    @GetMapping("/mfa/ott/request-code-ui")
    public String mfaOttRequestCodeUiPage(Model model, HttpServletRequest request) {
        FactorContext ctx = (FactorContext) request.getSession().getAttribute(SessionFactorContextManager.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx != null && ctx.getUsername() != null) {
            model.addAttribute("username", ctx.getUsername()); // username을 모델에 추가
            model.addAttribute("mfaSessionId", ctx.getMfaSessionId()); // JS에서 사용
        } else {
            model.addAttribute("errorMessage", "MFA 세션 정보를 찾을 수 없습니다.");
        }
        // 이 페이지의 폼 action은 /mfa/ott/generate (POST) 를 가리켜야 함.
        return "login-mfa-ott-request-code"; // 새로운 HTML 템플릿
    }


    // MFA 플로우용 OTT 코드 "입력" UI
    @GetMapping("/mfa/challenge/ott")
    public String mfaVerifyOttPage(Model model, HttpServletRequest request) {
        FactorContext ctx = (FactorContext) request.getSession().getAttribute(SessionFactorContextManager.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx != null && ctx.getUsername() != null) {
            model.addAttribute("usernameForDisplay", ctx.getUsername()); // 화면 표시용
            model.addAttribute("mfaSessionId", ctx.getMfaSessionId()); // JS에서 사용
            // HTML data-* 속성으로 loginProcessingUrl을 전달하기 위한 정보
            AuthenticationFlowConfig flowConfig = findFlowConfigByName(ctx.getFlowTypeName(), request);
            if (flowConfig != null) {
                Optional<AuthenticationStepConfig> ottStep = findStepConfigByFactorTypeAndMinOrder(flowConfig, AuthType.OTT, 0);
                ottStep.ifPresent(step -> {
                    if (step.getOptions().get("_options") instanceof io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions ottOpts) {
                        model.addAttribute("mfaOttProcessingUrl", ottOpts.getLoginProcessingUrl());
                    }
                });
            }
        } else {
            model.addAttribute("errorMessage", "MFA 세션 정보를 찾을 수 없습니다.");
        }
        return "login-mfa-verify-ott";
    }

    // MFA 플로우용 Passkey 인증 UI
    @GetMapping("/mfa/challenge/passkey")
    public String mfaVerifyPasskeyPage(Model model, HttpServletRequest request) {
        FactorContext ctx = (FactorContext) request.getSession().getAttribute(SessionFactorContextManager.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME);
        if (ctx != null && ctx.getUsername() != null) {
            model.addAttribute("mfaSessionId", ctx.getMfaSessionId());
            AuthenticationFlowConfig flowConfig = findFlowConfigByName(ctx.getFlowTypeName(), request);
            if (flowConfig != null) {
                Optional<AuthenticationStepConfig> passkeyStep = findStepConfigByFactorTypeAndMinOrder(flowConfig, AuthType.PASSKEY, 0);
                passkeyStep.ifPresent(step -> {
                    if (step.getOptions().get("_options") instanceof io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions pkOpts) {
                        model.addAttribute("mfaPasskeyProcessingUrl", pkOpts.getLoginProcessingUrl());
                        model.addAttribute("mfaPasskeyAssertionOptionsUrl", pkOpts.getAssertionOptionsEndpoint());
                    }
                });
            }
        } else {
            model.addAttribute("errorMessage", "MFA 세션 정보를 찾을 수 없습니다.");
        }
        return "login-mfa-verify-passkey";
    }

    @GetMapping("/mfa/failure")
    public String mfaFailurePage(@RequestParam(required = false) String error, Model model) {
        model.addAttribute("errorMessage", error != null ? error : "MFA 인증에 실패했습니다. 다시 시도해주세요.");
        return "mfa-failure";
    }

    // ... (logoutPage, findFlowConfigByName, findStepConfigByFactorTypeAndMinOrder 등 헬퍼 메소드)
    @Nullable
    private AuthenticationFlowConfig findFlowConfigByName(String flowTypeName, HttpServletRequest request) {
        if (!StringUtils.hasText(flowTypeName)) return null;
        try {
            // PlatformContext를 통해 현재 요청에 매칭된 SecurityFilterChain에 대한 FlowConfig를 가져오는 것이 이상적.
            // 여기서는 ApplicationContext를 통해 PlatformConfig 전체를 가져와 필터링.
            ApplicationContext appContext = (ApplicationContext) request.getServletContext().getAttribute("org.springframework.web.context.WebApplicationContext.ROOT");
            if (appContext != null) {
                PlatformConfig platformConfig = appContext.getBean(PlatformConfig.class);
                if (platformConfig != null && platformConfig.getFlows() != null) {
                    return platformConfig.getFlows().stream()
                            .filter(flow -> flowTypeName.equalsIgnoreCase(flow.getTypeName()))
                            .findFirst()
                            .orElse(null);
                }
            }
        } catch (Exception e) { log.warn("Error finding flow config by name '{}': {}", flowTypeName, e.getMessage()); }
        return null;
    }

    private Optional<AuthenticationStepConfig> findStepConfigByFactorTypeAndMinOrder(AuthenticationFlowConfig flowConfig, AuthType factorType, int minOrderExclusive) {
        if (flowConfig == null || factorType == null || flowConfig.getStepConfigs() == null) {
            return Optional.empty();
        }
        return flowConfig.getStepConfigs().stream()
                .filter(step -> step.getOrder() > minOrderExclusive &&
                        factorType.name().equalsIgnoreCase(step.getType()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));
    }


    @GetMapping("/logout") // GET 요청으로 로그아웃 페이지를 보여주고, JS가 POST /api/auth/logout 호출
    public String logoutPage() {
        return "logout";
    }
}

