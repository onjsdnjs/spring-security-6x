package io.springsecurity.springsecurity6x.admin.controller;

import io.springsecurity.springsecurity6x.admin.service.PermissionService;
import io.springsecurity.springsecurity6x.admin.service.RoleService;
import io.springsecurity.springsecurity6x.domain.dto.RoleDto;
import io.springsecurity.springsecurity6x.entity.Permission;
import io.springsecurity.springsecurity6x.entity.Role;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.ArrayList;
import java.util.List;

@Controller
@RequiredArgsConstructor
public class RoleController {

	private final RoleService roleService;
	private final PermissionService permissionService; // PermissionService 주입
	private final ModelMapper modelMapper; // ModelMapper 주입

	@GetMapping
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('ROLE_READ')") // 권한 설정 예시
	public String getRoles(Model model) {
		List<Role> roles = roleService.getRoles();
		model.addAttribute("roles", roles);
		return "admin/roles";
	}

	@GetMapping("/register")
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('ROLE_CREATE')") // 권한 설정 예시
	public String registerRoleForm(Model model) {
		model.addAttribute("role", new RoleDto());
		model.addAttribute("permissionList", permissionService.getAllPermissions()); // 모든 Permission 목록
		model.addAttribute("selectedPermissionIds", new ArrayList<Long>()); // 선택된 권한 ID 목록 초기화
		return "admin/rolesdetails";
	}

	@PostMapping
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('ROLE_CREATE')") // 권한 설정 예시
	public String createRole(@ModelAttribute("role") RoleDto roleDto, RedirectAttributes ra) {
		Role role = modelMapper.map(roleDto, Role.class);
		// RoleService의 createRole 메서드는 permissionIds를 받도록 수정되었습니다.
		roleService.createRole(role, roleDto.getPermissionIds());
		ra.addFlashAttribute("message", "역할이 성공적으로 생성되었습니다!");
		return "redirect:/admin/roles";
	}

	@GetMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('ROLE_READ')") // 권한 설정 예시
	public String getRoleDetails(@PathVariable Long id, Model model) {
		Role role = roleService.getRole(id); // Fetch Join으로 Permissions 함께 가져옴
		RoleDto roleDto = modelMapper.map(role, RoleDto.class);

		// 현재 Role에 할당된 Permission들의 ID 목록을 DTO에 설정
		List<Long> selectedPermissionIds = role.getPermissions().stream()
				.map(Permission::getId)
				.toList();

		model.addAttribute("role", roleDto);
		model.addAttribute("permissionList", permissionService.getAllPermissions()); // 모든 Permission 목록
		model.addAttribute("selectedPermissionIds", selectedPermissionIds); // 현재 선택된 권한 ID 목록
		return "admin/rolesdetails";
	}

	@PostMapping("/{id}/edit") // 수정 요청을 처리할 새로운 매핑 추가
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('ROLE_UPDATE')") // 권한 설정 예시
	public String updateRole(@PathVariable Long id, @ModelAttribute("role") RoleDto roleDto, RedirectAttributes ra) {
		roleDto.setId(String.valueOf(id)); // ID를 DTO에 설정
		Role role = modelMapper.map(roleDto, Role.class);
		// RoleService의 updateRole 메서드는 permissionIds를 받도록 수정되었습니다.
		roleService.updateRole(role, roleDto.getPermissionIds());
		ra.addFlashAttribute("message", "역할이 성공적으로 업데이트되었습니다!");
		return "redirect:/admin/roles";
	}

	@GetMapping("/delete/{id}")
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('ROLE_DELETE')") // 권한 설정 예시
	public String deleteRole(@PathVariable Long id, RedirectAttributes ra) {
		roleService.deleteRole(id);
		ra.addFlashAttribute("message", "역할이 성공적으로 삭제되었습니다!");
		return "redirect:/admin/roles";
	}
}
