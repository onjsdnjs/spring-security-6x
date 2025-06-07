package io.springsecurity.springsecurity6x.admin.controller;

import io.springsecurity.springsecurity6x.admin.service.PermissionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/admin")
@RequiredArgsConstructor
@Slf4j
public class AdminController {
    private final PermissionService permissionService; // PermissionService 주입

    @GetMapping
//    @PreAuthorize("hasRole('ADMIN')") // ADMIN 역할만 접근 가능
    public String adminDashboard(Model model) {
        log.info("Accessing admin dashboard.");
        // 관리자 대시보드에 필요한 데이터 추가 (예: 통계 요약)
        return "admin/dashboard"; // dashboard.html 템플릿
    }
}
