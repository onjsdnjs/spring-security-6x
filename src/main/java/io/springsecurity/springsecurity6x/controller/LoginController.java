package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.service.ott.CodeStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;

@Controller
@RequiredArgsConstructor
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
    @GetMapping("/login/ott")
    public String loginOttByCode(@RequestParam String code, Model model) {
        OneTimeToken ott = codeStore.consume(code);
        if (ott == null) {
            model.addAttribute("errorMessage", "유효하지 않거나 만료된 인증 링크입니다.");
            return "login-ott"; // 오류 메시지와 함께 OTT 요청 페이지로
        }
        model.addAttribute("username", ott.getUsername());
        model.addAttribute("token", ott.getTokenValue());
        return "ott-forward"; // JS가 자동 POST하여 로그인 시도
    }

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

    @GetMapping("/mfa/verify/ott")
    public String mfaVerifyOttPage(Model model, HttpSession session) {
        // String username = (String) session.getAttribute("mfaUsername");
        // model.addAttribute("username", username);
        return "login-mfa-verify-ott";
    }

    @GetMapping("/mfa/verify/passkey")
    public String mfaVerifyPasskeyPage(Model model, HttpSession session) {
        // String username = (String) session.getAttribute("mfaUsername");
        // model.addAttribute("username", username);
        return "login-mfa-verify-passkey";
    }

    @GetMapping("/mfa/failure")
    public String mfaFailurePage(@RequestParam(required = false) String error, Model model) {
        // 실패 원인에 따라 다른 메시지를 보여줄 수 있도록 파라미터 추가 가능
        model.addAttribute("errorMessage", error != null ? error : "MFA 인증에 실패했습니다. 다시 시도해주세요.");
        return "mfa-failure";
    }


    @GetMapping("/logout") // GET 요청으로 로그아웃 페이지를 보여주고, JS가 POST /api/auth/logout 호출
    public String logoutPage() {
        return "logout";
    }
}

