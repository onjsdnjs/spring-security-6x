package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.ott.CodeStore;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class LoginController {

    private final CodeStore codeStore;

    @GetMapping("/loginForm")
    public String loginForm() {
        return "login-form";
    }

    @GetMapping("/loginOtt")
    public String loginOtt() {
        return "login-ott";
    }

    @GetMapping("/login/ott")
    public String loginOttByCode(@RequestParam String code, Model model) {
        OneTimeToken ott = codeStore.consume(code);
        if (ott == null) {
            throw new IllegalArgumentException("Invalid or expired code");
        }
        model.addAttribute("username", ott.getUsername());
        model.addAttribute("token", ott.getTokenValue());
        return "ott-forward";
    }

    @GetMapping("/ott/sent")
    public String sentPage(@RequestParam String email, Model model) {
        model.addAttribute("email", email);
        return "ott-sent";
    }

    @GetMapping("/loginPasskey")
    public String passkeyLogin() {
        return "login-passkey";
    }

    @GetMapping("/logout")
    public String logout() {
        return "logout";
    }

}

