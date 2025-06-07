package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.admin.service.PermissionService;
import io.springsecurity.springsecurity6x.admin.service.RoleService;
import io.springsecurity.springsecurity6x.domain.dto.MethodResourceDto;
import io.springsecurity.springsecurity6x.entity.MethodResource;
import io.springsecurity.springsecurity6x.security.authz.service.MethodResourceService;
import io.springsecurity.springsecurity6x.entity.Role; // Role 엔티티 임포트 (MethodResourceRole 관계 관리용)
import io.springsecurity.springsecurity6x.entity.Permission; // Permission 엔티티 임포트 (MethodResourcePermission 관계 관리용)

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.security.access.prepost.PreAuthorize; // @PreAuthorize 임포트
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin/method-resources") // 메서드 리소스 관리를 위한 공통 경로
@RequiredArgsConstructor
@Slf4j
public class MethodResourceController {

    private final MethodResourceService methodResourceService;
    private final RoleService roleService; // Role 서비스 주입
    private final PermissionService permissionService; // Permission 서비스 주입
    private final ModelMapper modelMapper;

    /**
     * MethodResource 목록 페이지를 반환합니다.
     * @param model Model 객체
     * @return admin/method-resources.html 템플릿 경로
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('METHOD_RESOURCE_READ')") // 권한 예시
    public String getMethodResources(Model model) {
        List<MethodResource> methodResources = methodResourceService.getAllMethodResources();
        model.addAttribute("methodResources", methodResources);
        log.info("Displaying method resources list. Total: {}", methodResources.size());
        return "admin/method-resources";
    }

    /**
     * 새 MethodResource 등록 폼 페이지를 반환합니다.
     * @param model Model 객체
     * @return admin/method-resource-details.html 템플릿 경로
     */
    @GetMapping("/register")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('METHOD_RESOURCE_CREATE')") // 권한 예시
    public String registerMethodResourceForm(Model model) {
        model.addAttribute("methodResource", new MethodResourceDto()); // 빈 DTO 객체 전달
        model.addAttribute("allRoles", roleService.getRoles()); // 모든 역할 목록
        model.addAttribute("allPermissions", permissionService.getAllPermissions()); // 모든 권한 목록
        model.addAttribute("selectedRoleIds", new HashSet<Long>()); // 선택된 역할 ID 초기화
        model.addAttribute("selectedPermissionIds", new HashSet<Long>()); // 선택된 권한 ID 초기화
        log.info("Displaying new method resource registration form.");
        return "admin/method-resource-details";
    }

    /**
     * 새 MethodResource를 생성하는 POST 요청을 처리합니다.
     * @param methodResourceDto 폼에서 전송된 데이터
     * @param ra RedirectAttributes for flash messages
     * @return 리다이렉트 경로
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('METHOD_RESOURCE_CREATE')") // 권한 예시
    public String createMethodResource(@ModelAttribute("methodResource") MethodResourceDto methodResourceDto,
                                       @RequestParam(value = "selectedRoleIds", required = false) List<Long> selectedRoleIds,
                                       @RequestParam(value = "selectedPermissionIds", required = false) List<Long> selectedPermissionIds,
                                       RedirectAttributes ra) {
        try {
            MethodResource methodResource = modelMapper.map(methodResourceDto, MethodResource.class);

            // 역할 및 권한 연결 (조인 엔티티를 통해)
            Set<Role> roles = new HashSet<>();
            if (selectedRoleIds != null) {
                roles = selectedRoleIds.stream()
                        .map(roleService::getRole)
                        .filter(r -> r != null && r.getId() != null) // Optional 대신 직접 Role 반환하도록 Service 수정했다면 Optional 제거
                        .collect(Collectors.toSet());
            }

            Set<Permission> permissions = new HashSet<>();
            if (selectedPermissionIds != null) {
                permissions = selectedPermissionIds.stream()
                        .map(permissionService::getPermission)
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .collect(Collectors.toSet());
            }

            // 서비스에서 조인 엔티티 관계를 처리하도록 위임
            methodResourceService.createMethodResource(methodResource, roles, permissions);

            ra.addFlashAttribute("message", "MethodResource '" + methodResource.getMethodName() + "'이 성공적으로 생성되었습니다.");
            log.info("MethodResource created: {}", methodResource.getClassName() + "." + methodResource.getMethodName());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.warn("Failed to create MethodResource: {}", e.getMessage());
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "MethodResource 생성 중 알 수 없는 오류 발생: " + e.getMessage());
            log.error("Error creating MethodResource", e);
        }
        return "redirect:/admin/method-resources";
    }

    /**
     * 특정 MethodResource의 상세 정보 및 수정 폼 페이지를 반환합니다.
     * @param id 조회할 MethodResource ID
     * @param model Model 객체
     * @return admin/method-resource-details.html 템플릿 경로
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('METHOD_RESOURCE_READ')") // 권한 예시
    public String methodResourceDetails(@PathVariable Long id, Model model) {
        MethodResource methodResource = methodResourceService.getMethodResource(id)
                .orElseThrow(() -> new IllegalArgumentException("Invalid MethodResource ID: " + id));

        MethodResourceDto methodResourceDto = modelMapper.map(methodResource, MethodResourceDto.class);

        // 현재 MethodResource에 할당된 역할 및 권한 ID 목록을 추출
        Set<Long> selectedRoleIds = methodResource.getMethodResourceRoles().stream()
                .map(mrr -> mrr.getRole().getId())
                .collect(Collectors.toSet());
        Set<Long> selectedPermissionIds = methodResource.getMethodResourcePermissions().stream()
                .map(mrp -> mrp.getPermission().getId())
                .collect(Collectors.toSet());

        model.addAttribute("methodResource", methodResourceDto);
        model.addAttribute("allRoles", roleService.getRoles());
        model.addAttribute("allPermissions", permissionService.getAllPermissions());
        model.addAttribute("selectedRoleIds", selectedRoleIds);
        model.addAttribute("selectedPermissionIds", selectedPermissionIds);
        log.info("Displaying details for MethodResource ID: {}", id);
        return "admin/method-resource-details";
    }

    /**
     * 특정 MethodResource를 업데이트하는 POST 요청을 처리합니다.
     * @param id 업데이트할 MethodResource ID
     * @param methodResourceDto 폼에서 전송된 데이터
     * @param ra RedirectAttributes for flash messages
     * @return 리다이렉트 경로
     */
    @PostMapping("/{id}/edit")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('METHOD_RESOURCE_UPDATE')") // 권한 예시
    public String updateMethodResource(@PathVariable Long id,
                                       @ModelAttribute("methodResource") MethodResourceDto methodResourceDto,
                                       @RequestParam(value = "selectedRoleIds", required = false) List<Long> selectedRoleIds,
                                       @RequestParam(value = "selectedPermissionIds", required = false) List<Long> selectedPermissionIds,
                                       RedirectAttributes ra) {
        try {
            methodResourceDto.setId(id); // URL 경로에서 받은 ID를 DTO에 설정
            MethodResource methodResource = modelMapper.map(methodResourceDto, MethodResource.class);

            Set<Role> roles = new HashSet<>();
            if (selectedRoleIds != null) {
                roles = selectedRoleIds.stream()
                        .map(roleService::getRole)
                        .filter(r -> r != null && r.getId() != null)
                        .collect(Collectors.toSet());
            }

            Set<Permission> permissions = new HashSet<>();
            if (selectedPermissionIds != null) {
                permissions = selectedPermissionIds.stream()
                        .map(permissionService::getPermission)
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .collect(Collectors.toSet());
            }

            methodResourceService.updateMethodResource(methodResource, roles, permissions);

            ra.addFlashAttribute("message", "MethodResource '" + methodResource.getMethodName() + "'이 성공적으로 업데이트되었습니다.");
            log.info("MethodResource updated: {}", methodResource.getClassName() + "." + methodResource.getMethodName());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.warn("Failed to update MethodResource: {}", e.getMessage());
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "MethodResource 업데이트 중 알 수 없는 오류 발생: " + e.getMessage());
            log.error("Error updating MethodResource", e);
        }
        return "redirect:/admin/method-resources";
    }

    /**
     * 특정 MethodResource를 삭제하는 GET 요청을 처리합니다.
     * @param id 삭제할 MethodResource ID
     * @param ra RedirectAttributes for flash messages
     * @return 리다이렉트 경로
     */
    @GetMapping("/delete/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('METHOD_RESOURCE_DELETE')") // 권한 예시
    public String deleteMethodResource(@PathVariable Long id, RedirectAttributes ra) {
        try {
            methodResourceService.deleteMethodResource(id);
            ra.addFlashAttribute("message", "MethodResource (ID: " + id + ")이 성공적으로 삭제되었습니다.");
            log.info("MethodResource deleted: ID {}", id);
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "MethodResource 삭제 중 오류 발생: " + e.getMessage());
            log.error("Error deleting MethodResource ID: {}", id, e);
        }
        return "redirect:/admin/method-resources";
    }
}
