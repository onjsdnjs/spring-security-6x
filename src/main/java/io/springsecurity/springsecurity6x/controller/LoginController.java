package io.springsecurity.springsecurity6x.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class LoginController {

    @GetMapping("/loginForm")
    public String loginForm() {
        return "login-form";
    }

    @GetMapping("/loginOtt")
    public String userListPage() {
        return "login-ott";
    }

    @GetMapping("/loginPasskey")
    public String passkeyLogin() {
        return "login-passkey";
    }

    @GetMapping("/2fa-choice")
    public String choose2fa() {
        return "2fa-choice";
    }

    @GetMapping("/logout")
    public String logout() {
        return "logout";
    }

}

