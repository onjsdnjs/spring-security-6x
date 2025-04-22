/*
package io.springsecurity.springsecurity6x.ott;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class OttController {

    @PostMapping("/ott/generate")
    public String generateToken(@RequestParam String username, HttpServletRequest request) {
        // OneTimeTokenLoginFilter 가 내부적으로 토큰을 생성하도록
        // POST /ott/generate 를 SecurityFilterChain 앞단에서 가로채 처리.
        // 컨트롤러는 실제로 호출되지 않지만, "404" 방지를 위해 작성하거나
        // 추가 정보를 모델에 담아 뷰로 넘길 수 있다.
        return "redirect:/ott/sent";
    }

    @GetMapping("/ott/sent")
    public String sentPage() {
        return "ott-sent";   // src/main/resources/templates/ott-sent.html
    }

    @GetMapping("/")
    public String home() {
        return "home"; }
}
*/
