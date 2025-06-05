package io.springsecurity.springsecurity6x.admin.controller;

import io.springsecurity.springsecurity6x.admin.repository.RoleRepository;
import io.springsecurity.springsecurity6x.admin.service.ResourcesService;
import io.springsecurity.springsecurity6x.admin.service.RoleService;
import io.springsecurity.springsecurity6x.domain.dto.ResourcesDto;
import io.springsecurity.springsecurity6x.entity.Resources;
import io.springsecurity.springsecurity6x.entity.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j // Slf4j 어노테이션 추가
@Controller
@RequestMapping("/admin/resources")
@RequiredArgsConstructor
public class ResourcesController {

	private final ResourcesService resourcesService;
	private final RoleRepository roleRepository; // 직접 주입
	private final RoleService roleService; // 직접 주입
	private final ModelMapper modelMapper; // ModelMapper 직접 주입

	@GetMapping
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('RESOURCE_READ')") // 권한 예시
	public String getResources(Model model) {
		List<Resources> resources = resourcesService.getResources();
		model.addAttribute("resources", resources);
		return "admin/resources";
	}

	@PostMapping
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('RESOURCE_CREATE')") // 권한 예시
	public String createResources(@ModelAttribute ResourcesDto resourcesDto, RedirectAttributes ra) { // @ModelAttribute 어노테이션 추가
		try {
			Resources resources = modelMapper.map(resourcesDto, Resources.class);

			// Role 매핑 (ResourcesRole 조인 엔티티 사용)
			Set<Role> roles = new HashSet<>();
			if (resourcesDto.getRoleName() != null) { // ResourcesDto에 roleName 필드가 있다고 가정
				Optional<Role> roleOpt = roleRepository.findByRoleName(resourcesDto.getRoleName());
				roleOpt.ifPresent(roles::add);
			}
			// resources.setRoleSet(roles); // 기존 ManyToMany 필드 제거됨

			// ResourcesService에서 조인 엔티티 관계를 처리하도록 위임
			resourcesService.createResources(resources, roles);

			ra.addFlashAttribute("message", "자원이 성공적으로 생성되었습니다!");
			log.info("Resources created: {}", resources.getResourceName());
		} catch (IllegalArgumentException e) {
			ra.addFlashAttribute("errorMessage", e.getMessage());
			log.warn("Failed to create resource: {}", e.getMessage());
		} catch (Exception e) {
			ra.addFlashAttribute("errorMessage", "자원 생성 중 알 수 없는 오류 발생: " + e.getMessage());
			log.error("Error creating resource", e);
		}
		return "redirect:/admin/resources";
	}

	@GetMapping(value="/register")
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('RESOURCE_CREATE')") // 권한 예시
	public String resourcesRegister(Model model) {
		List<Role> roleList = roleService.getRoles();
		model.addAttribute("roleList", roleList);

		ResourcesDto resources = new ResourcesDto();
		// Set<Role> roleSet = new HashSet<>(); // 더 이상 필요 없음
		// roleSet.add(new Role()); // 더 이상 필요 없음
		// resources.setRoleSet(roleSet); // 더 이상 필요 없음

		// ResourcesDto에 selectedRoleIds 필드가 있다고 가정하고 초기화
		model.addAttribute("selectedRoleIds", new HashSet<Long>()); // 선택된 역할 ID 목록 초기화
		model.addAttribute("resources", resources);
		return "admin/resourcesdetails";
	}

	@GetMapping(value="/{id}")
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('RESOURCE_READ')") // 권한 예시
	public String resourceDetails(@PathVariable Long id, Model model) { // Long으로 타입 변경
		List<Role> roleList = roleService.getRoles();
		model.addAttribute("roleList", roleList);

		Resources resources = resourcesService.getResources(id); // ID 타입 Long으로 변경
		// 기존 resources.getRoleSet().stream().map(role -> role.getRoleName()).toList(); 대신
		// resources.getResourcesRoles()에서 역할 이름 목록 추출
		List<String> myRoles = resources.getResourcesRoles().stream()
				.map(rr -> rr.getRole().getRoleName())
				.collect(Collectors.toList());

		// 현재 Resources에 할당된 Role들의 ID 목록을 DTO에 설정 (수정 폼용)
		Set<Long> selectedRoleIds = resources.getResourcesRoles().stream()
				.map(rr -> rr.getRole().getId())
				.collect(Collectors.toSet());

		ResourcesDto resourcesDto = modelMapper.map(resources, ResourcesDto.class);
		resourcesDto.setRoleName(myRoles.isEmpty() ? null : myRoles.get(0)); // 기존 DTO 필드 사용
		model.addAttribute("selectedRoleIds", selectedRoleIds); // 선택된 역할 ID 목록 전달

		model.addAttribute("resources", resourcesDto);
		return "admin/resourcesdetails";
	}

	@PostMapping(value="/{id}/edit") // 수정 요청 POST 매핑 추가
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('RESOURCE_UPDATE')") // 권한 예시
	public String updateResources(@PathVariable Long id, @ModelAttribute ResourcesDto resourcesDto, RedirectAttributes ra) { // Long으로 타입 변경
		try {
			resourcesDto.setId(id); // ID를 DTO에 설정
			Resources resources = modelMapper.map(resourcesDto, Resources.class);

			Set<Role> roles = new HashSet<>();
			if (resourcesDto.getRoleName() != null) {
				Optional<Role> roleOpt = roleRepository.findByRoleName(resourcesDto.getRoleName());
				roleOpt.ifPresent(roles::add);
			}
			// ResourcesService에서 조인 엔티티 관계를 처리하도록 위임
			resourcesService.updateResources(resources, roles);

			ra.addFlashAttribute("message", "자원이 성공적으로 업데이트되었습니다!");
			log.info("Resources updated: {}", resources.getResourceName());
		} catch (IllegalArgumentException e) {
			ra.addFlashAttribute("errorMessage", e.getMessage());
			log.warn("Failed to update resource: {}", e.getMessage());
		} catch (Exception e) {
			ra.addFlashAttribute("errorMessage", "자원 업데이트 중 알 수 없는 오류 발생: " + e.getMessage());
			log.error("Error updating resource", e);
		}
		return "redirect:/admin/resources";
	}

	@GetMapping(value="/delete/{id}")
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('RESOURCE_DELETE')") // 권한 예시
	public String removeResources(@PathVariable Long id, RedirectAttributes ra) throws Exception { // Long으로 타입 변경
		try {
			resourcesService.deleteResources(id);
			ra.addFlashAttribute("message", "자원 (ID: " + id + ")이 성공적으로 삭제되었습니다!");
			log.info("Resources deleted: ID {}", id);
		} catch (Exception e) {
			ra.addFlashAttribute("errorMessage", "자원 삭제 중 오류 발생: " + e.getMessage());
			log.error("Error deleting resource ID: {}", id, e);
		}
		return "redirect:/admin/resources";
	}
}