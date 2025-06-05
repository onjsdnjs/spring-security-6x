package io.springsecurity.springsecurity6x.admin.controller;

import io.springsecurity.springsecurity6x.admin.service.RoleService;
import io.springsecurity.springsecurity6x.domain.dto.RoleDto;
import io.springsecurity.springsecurity6x.entity.Permission;
import io.springsecurity.springsecurity6x.entity.Role;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Controller
@RequiredArgsConstructor
public class RoleController {

	private final RoleService roleService;
	private final PermissionSer roleService;

	@GetMapping(value="/admin/roles")
	public String getRoles(Model model) {

		List<Role> roles = roleService.getRoles();
		model.addAttribute("roles", roles);

		return "admin/roles";
	}

	@GetMapping(value="/admin/roles/register")
	public String rolesRegister(Model model) {

		RoleDto role = new RoleDto();
		model.addAttribute("roles", role);
		model.addAttribute("permissionList", permissionService.getAllPermissions()); // 모든 Permission 목록

		return "admin/rolesdetails";
	}

	@PostMapping(value="/admin/roles")
	public String createRole(RoleDto roleDto) {
		ModelMapper modelMapper = new ModelMapper();
		Role role = modelMapper.map(roleDto, Role.class);
		// DTO 에서 선택된 Permission ID들을 받아와 Permission 엔티티 조회 후 Set<Permission> 구성
		Set<Permission> selectedPermissions = new HashSet<>();
		if (roleDto.getPermissionIds() != null) { // DTO에 permissionIds 필드 추가 필요
			roleDto.getPermissionIds().forEach(permId -> {
				permissionRepository.findById(permId).ifPresent(selectedPermissions::add);
			});
		}
		role.setPermissions(selectedPermissions); // Role 엔티티에 permissions 설정
		roleService.createRole(role);
		return "redirect:/admin/roles";
	}

	@GetMapping(value="/admin/roles/{id}")
	public String getRole(@PathVariable String id, Model model) {
		Role role = roleService.getRole(Long.parseLong(id));

		ModelMapper modelMapper = new ModelMapper();
		RoleDto roleDto = modelMapper.map(role, RoleDto.class);
		model.addAttribute("roles", roleDto);

		return "admin/rolesdetails";
	}

	@GetMapping(value="/admin/roles/delete/{id}")
	public String removeRoles(@PathVariable String id) {

		roleService.deleteRole(Long.parseLong(id));

		return "redirect:/admin/roles";
	}
}
