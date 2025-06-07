package io.springsecurity.springsecurity6x.admin.controller;

import io.springsecurity.springsecurity6x.admin.service.PermissionService;
import io.springsecurity.springsecurity6x.domain.dto.PermissionDto;
import io.springsecurity.springsecurity6x.entity.Permission;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
@RequestMapping("/admin/permissions") // 권한 관리를 위한 공통 경로 설정
@RequiredArgsConstructor
@Slf4j
public class PermissionController {

    private final PermissionService permissionService;
    private final ModelMapper modelMapper;

    /**
     * 권한 목록 페이지를 반환합니다.
     * @param model Model 객체
     * @return admin/permissions.html 템플릿 경로
     */
    @GetMapping
//    @PreAuthorize("hasRole('ADMIN') or hasAuthority('PERMISSION_READ')") // ADMIN 역할 또는 PERMISSION_READ 권한 필요
    public String getPermissions(Model model) {
        List<Permission> permissions = permissionService.getAllPermissions();
        model.addAttribute("permissions", permissions);
        log.info("Displaying permissions list. Total: {}", permissions.size());
        return "admin/permissions";
    }

    /**
     * 새 권한 등록 폼 페이지를 반환합니다.
     * @param model Model 객체
     * @return admin/permissiondetails.html 템플릿 경로
     */
    @GetMapping("/register")
//    @PreAuthorize("hasRole('ADMIN') or hasAuthority('PERMISSION_CREATE')") // ADMIN 역할 또는 PERMISSION_CREATE 권한 필요
    public String registerPermissionForm(Model model) {
        model.addAttribute("permission", new PermissionDto()); // 빈 DTO 객체 전달
        log.info("Displaying new permission registration form.");
        return "admin/permissiondetails";
    }

    /**
     * 새 권한을 생성하는 POST 요청을 처리합니다.
     * @param permissionDto 폼에서 전송된 Permission 데이터
     * @param ra RedirectAttributes for flash messages
     * @return 리다이렉트 경로
     */
    @PostMapping
//    @PreAuthorize("hasRole('ADMIN') or hasAuthority('PERMISSION_CREATE')") // ADMIN 역할 또는 PERMISSION_CREATE 권한 필요
    public String createPermission(@ModelAttribute("permission") PermissionDto permissionDto, RedirectAttributes ra) {
        try {
            Permission permission = modelMapper.map(permissionDto, Permission.class);
            permissionService.createPermission(permission);
            ra.addFlashAttribute("message", "권한 '" + permission.getName() + "'이 성공적으로 생성되었습니다.");
            log.info("Permission created: {}", permission.getName());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.warn("Failed to create permission: {}", e.getMessage());
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "권한 생성 중 알 수 없는 오류 발생: " + e.getMessage());
            log.error("Error creating permission", e);
        }
        return "redirect:/admin/permissions";
    }

    /**
     * 특정 권한의 상세 정보 및 수정 폼 페이지를 반환합니다.
     * @param id 조회할 권한 ID
     * @param model Model 객체
     * @return admin/permissiondetails.html 템플릿 경로
     */
    @GetMapping("/{id}")
//    @PreAuthorize("hasRole('ADMIN') or hasAuthority('PERMISSION_READ')") // ADMIN 역할 또는 PERMISSION_READ 권한 필요
    public String permissionDetails(@PathVariable Long id, Model model) {
        Permission permission = permissionService.getPermission(id)
                .orElseThrow(() -> new IllegalArgumentException("Invalid permission ID: " + id));
        model.addAttribute("permission", modelMapper.map(permission, PermissionDto.class));
        log.info("Displaying details for permission ID: {}", id);
        return "admin/permissiondetails";
    }

    /**
     * 특정 권한을 업데이트하는 POST 요청을 처리합니다.
     * @param id 업데이트할 권한 ID
     * @param permissionDto 폼에서 전송된 Permission 데이터
     * @param ra RedirectAttributes for flash messages
     * @return 리다이렉트 경로
     */
    @PostMapping("/{id}/edit")
//    @PreAuthorize("hasRole('ADMIN') or hasAuthority('PERMISSION_UPDATE')") // ADMIN 역할 또는 PERMISSION_UPDATE 권한 필요
    public String updatePermission(@PathVariable Long id, @ModelAttribute("permission") PermissionDto permissionDto, RedirectAttributes ra) {
        try {
            permissionDto.setId(id); // URL 경로에서 받은 ID를 DTO에 설정
            Permission permission = modelMapper.map(permissionDto, Permission.class);
            permissionService.updatePermission(permission);
            ra.addFlashAttribute("message", "권한 '" + permission.getName() + "'이 성공적으로 업데이트되었습니다.");
            log.info("Permission updated: {}", permission.getName());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.warn("Failed to update permission: {}", e.getMessage());
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "권한 업데이트 중 알 수 없는 오류 발생: " + e.getMessage());
            log.error("Error updating permission", e);
        }
        return "redirect:/admin/permissions";
    }

    /**
     * 특정 권한을 삭제하는 GET 요청을 처리합니다.
     * @param id 삭제할 권한 ID
     * @param ra RedirectAttributes for flash messages
     * @return 리다이렉트 경로
     */
    @GetMapping("/delete/{id}")
//    @PreAuthorize("hasRole('ADMIN') or hasAuthority('PERMISSION_DELETE')") // ADMIN 역할 또는 PERMISSION_DELETE 권한 필요
    public String deletePermission(@PathVariable Long id, RedirectAttributes ra) {
        try {
            permissionService.deletePermission(id);
            ra.addFlashAttribute("message", "권한 (ID: " + id + ")이 성공적으로 삭제되었습니다.");
            log.info("Permission deleted: ID {}", id);
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "권한 삭제 중 오류 발생: " + e.getMessage());
            log.error("Error deleting permission ID: {}", id, e);
        }
        return "redirect:/admin/permissions";
    }
}
