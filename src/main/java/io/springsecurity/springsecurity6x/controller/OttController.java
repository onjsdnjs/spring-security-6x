package io.springsecurity.springsecurity6x.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class OttController {

    @GetMapping("/ott/sent")
    public String sentPage() {
        return "ott-token-sent";   // src/main/resources/templates/ott-sent.html
    }
}
