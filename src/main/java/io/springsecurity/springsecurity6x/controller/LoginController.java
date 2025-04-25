package io.springsecurity.springsecurity6x.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class LoginController {

    @GetMapping("/loginForm")
    public String loginForm() {
        return "login-form";
    }

    @GetMapping("/loginOtt")
    public String loginOtt() {
        return "login-ott";
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

