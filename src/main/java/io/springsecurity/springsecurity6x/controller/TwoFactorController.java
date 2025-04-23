package io.springsecurity.springsecurity6x.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class TwoFactorController {

    @GetMapping("/2faChoice")
    public String choose2fa(
            @RequestParam(required = false) String method,
            @RequestParam(defaultValue = "false") boolean skip2fa,
            HttpSession session,
            Model model) {

        if (skip2fa) {
            if ("otp".equalsIgnoreCase(method))   return "redirect:/loginOtt";
            if ("passkey".equalsIgnoreCase(method))return "redirect:/loginPasskey";
            return "redirect:/login-form";
        }

        // 세션에 저장된 username/email 예시
        model.addAttribute("session", session);
        return "2fa-choice";
    }
}

