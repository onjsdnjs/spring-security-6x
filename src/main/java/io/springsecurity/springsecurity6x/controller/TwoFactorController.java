package io.springsecurity.springsecurity6x.controller;

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
            Model model
    ) {
        // 1) skip2fa=true => 바로 1차 인증 페이지로 이동
        if (skip2fa) {
            if ("otp".equalsIgnoreCase(method)) {
                return "redirect:/login-ott";
            }
            if ("passkey".equalsIgnoreCase(method)) {
                return "redirect:/login-passkey";
            }
            // 기본은 form
            return "redirect:/login-form";
        }

        // 2) 2FA 선택 페이지로 렌더링
        model.addAttribute("selectedMethod", method);
        return "2fa-choice";
    }
}

