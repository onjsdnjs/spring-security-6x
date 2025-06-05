package io.springsecurity.springsecurity6x.admin.controller;

import io.springsecurity.springsecurity6x.admin.service.impl.RoleHierarchyService;
import io.springsecurity.springsecurity6x.domain.dto.RoleHierarchyDto;
import io.springsecurity.springsecurity6x.entity.RoleHierarchyEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping("/admin/role-hierarchies")
@RequiredArgsConstructor
@Slf4j
public class RoleHierarchyController {

    private final RoleHierarchyService roleHierarchyService;
    private final ModelMapper modelMapper;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('ROLE_HIERARCHY_READ')") // 권한 예시
    public String getRoleHierarchies(Model model) {
        List<RoleHierarchyEntity> hierarchies = roleHierarchyService.getAllRoleHierarchies();
        model.addAttribute("hierarchies", hierarchies);
        log.info("Displaying role hierarchies list. Total: {}", hierarchies.size());
        return "admin/role-hierarchies"; // admin/role-hierarchies.html 템플릿
    }

    @GetMapping("/register")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('ROLE_HIERARCHY_CREATE')") // 권한 예시
    public String registerRoleHierarchyForm(Model model) {
        model.addAttribute("hierarchy", new RoleHierarchyDto()); // 빈 DTO 객체 전달
        log.info("Displaying new role hierarchy registration form.");
        return "admin/role-hierarchy-details"; // admin/role-hierarchy-details.html 템플릿
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('ROLE_HIERARCHY_CREATE')") // 권한 예시
    public String createRoleHierarchy(@ModelAttribute("hierarchy") RoleHierarchyDto hierarchyDto, RedirectAttributes ra) {
        try {
            RoleHierarchyEntity entity = modelMapper.map(hierarchyDto, RoleHierarchyEntity.class);
            roleHierarchyService.createRoleHierarchy(entity);
            ra.addFlashAttribute("message", "역할 계층이 성공적으로 생성되었습니다!");
            log.info("Role hierarchy created: {}", entity.getHierarchyString());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.warn("Failed to create role hierarchy: {}", e.getMessage());
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "역할 계층 생성 중 알 수 없는 오류 발생: " + e.getMessage());
            log.error("Error creating role hierarchy", e);
        }
        return "redirect:/admin/role-hierarchies";
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('ROLE_HIERARCHY_READ')") // 권한 예시
    public String roleHierarchyDetails(@PathVariable Long id, Model model) {
        RoleHierarchyEntity entity = roleHierarchyService.getRoleHierarchy(id)
                .orElseThrow(() -> new IllegalArgumentException("Invalid RoleHierarchy ID: " + id));
        model.addAttribute("hierarchy", modelMapper.map(entity, RoleHierarchyDto.class));
        log.info("Displaying details for role hierarchy ID: {}", id);
        return "admin/role-hierarchy-details";
    }

    @PostMapping("/{id}/edit")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('ROLE_HIERARCHY_UPDATE')") // 권한 예시
    public String updateRoleHierarchy(@PathVariable Long id, @ModelAttribute("hierarchy") RoleHierarchyDto hierarchyDto, RedirectAttributes ra) {
        try {
            hierarchyDto.setId(id); // URL 경로에서 받은 ID를 DTO에 설정
            RoleHierarchyEntity entity = modelMapper.map(hierarchyDto, RoleHierarchyEntity.class);
            roleHierarchyService.updateRoleHierarchy(entity);
            ra.addFlashAttribute("message", "역할 계층이 성공적으로 업데이트되었습니다!");
            log.info("Role hierarchy updated: {}", entity.getHierarchyString());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.warn("Failed to update role hierarchy: {}", e.getMessage());
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "역할 계층 업데이트 중 알 수 없는 오류 발생: " + e.getMessage());
            log.error("Error updating role hierarchy", e);
        }
        return "redirect:/admin/role-hierarchies";
    }

    @GetMapping("/delete/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('ROLE_HIERARCHY_DELETE')") // 권한 예시
    public String deleteRoleHierarchy(@PathVariable Long id, RedirectAttributes ra) {
        try {
            roleHierarchyService.deleteRoleHierarchy(id);
            ra.addFlashAttribute("message", "역할 계층 (ID: " + id + ")이 성공적으로 삭제되었습니다!");
            log.info("Role hierarchy deleted: ID {}", id);
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "역할 계층 삭제 중 오류 발생: " + e.getMessage());
            log.error("Error deleting role hierarchy ID: {}", id, e);
        }
        return "redirect:/admin/role-hierarchies";
    }

    @PostMapping("/{id}/activate")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('ROLE_HIERARCHY_ACTIVATE')") // 권한 예시
    public String activateRoleHierarchy(@PathVariable Long id, RedirectAttributes ra) {
        try {
            roleHierarchyService.activateRoleHierarchy(id);
            ra.addFlashAttribute("message", "역할 계층 (ID: " + id + ")이 활성화되었습니다!");
            log.info("Role hierarchy activated: ID {}", id);
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "역할 계층 활성화 중 오류 발생: " + e.getMessage());
            log.error("Error activating role hierarchy ID: {}", id, e);
        }
        return "redirect:/admin/role-hierarchies";
    }
}