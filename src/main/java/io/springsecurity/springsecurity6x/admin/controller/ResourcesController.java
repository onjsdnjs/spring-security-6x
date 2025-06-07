package io.springsecurity.springsecurity6x.admin.controller; // 패키지명 확인

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
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Controller
@RequestMapping("/admin/resources")
@RequiredArgsConstructor
public class ResourcesController {

	private final ResourcesService resourcesService;
	private final RoleService roleService; // RoleService 주입
	private final ModelMapper modelMapper; // ModelMapper 직접 주입

	@GetMapping
//	@PreAuthorize("hasRole('ADMIN') or hasAuthority('RESOURCE_READ')")
	public String getResources(Model model) {
		List<Resources> resources = resourcesService.getResources();
		model.addAttribute("resources", resources);
		return "admin/resources";
	}

	@PostMapping
//	@PreAuthorize("hasRole('ADMIN') or hasAuthority('RESOURCE_CREATE')")
	public String createResources(@ModelAttribute ResourcesDto resourcesDto,
								  @RequestParam(value = "selectedRoleIds", required = false) List<Long> selectedRoleIds, // @RequestParam으로 ID 목록 받기
								  RedirectAttributes ra) {
		try {
			Resources resources = modelMapper.map(resourcesDto, Resources.class);

			// Role 엔티티 조회 (List<Long> selectedRoleIds -> Set<Role>)
			Set<Role> roles = new HashSet<>();
			if (selectedRoleIds != null && !selectedRoleIds.isEmpty()) {
				roles = selectedRoleIds.stream()
						.map(roleService::getRole) // RoleService.getRole(id)는 Optional을 반환
						.filter(r -> r != null) // Optional에서 엔티티를 추출
						.collect(Collectors.toSet());
			}

			// ResourcesService에서 조인 엔티티 관계를 처리하도록 위임
			resourcesService.createResources(resources, roles);

			ra.addFlashAttribute("message", "자원 '" + resources.getResourceName() + "'이 성공적으로 생성되었습니다!");
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

	@GetMapping(value = "/register")
//	@PreAuthorize("hasRole('ADMIN') or hasAuthority('RESOURCE_CREATE')")
	public String resourcesRegister(Model model) {
		List<Role> roleList = roleService.getRoles();
		model.addAttribute("roleList", roleList);

		ResourcesDto resources = new ResourcesDto();
		model.addAttribute("selectedRoleIds", new HashSet<Long>()); // 선택된 역할 ID 목록 초기화
		model.addAttribute("resources", resources);
		return "admin/resourcesdetails";
	}

	@GetMapping(value = "/{id}")
//	@PreAuthorize("hasRole('ADMIN') or hasAuthority('RESOURCE_READ')")
	public String resourceDetails(@PathVariable Long id, Model model) {
		List<Role> roleList = roleService.getRoles();
		model.addAttribute("roleList", roleList);

		Resources resources = resourcesService.getResources(id); // ID 타입 Long

		// 현재 Resources에 할당된 Role들의 ID 목록을 추출 (수정 폼용)
		Set<Long> selectedRoleIds = resources.getResourcesRoles().stream()
				.map(rr -> rr.getRole().getId())
				.collect(Collectors.toSet());

		ResourcesDto resourcesDto = modelMapper.map(resources, ResourcesDto.class);
		model.addAttribute("selectedRoleIds", selectedRoleIds); // 선택된 역할 ID 목록 전달

		model.addAttribute("resources", resourcesDto);
		return "admin/resourcesdetails";
	}

	@PostMapping(value = "/{id}/edit") // 수정 요청 POST 매핑
//	@PreAuthorize("hasRole('ADMIN') or hasAuthority('RESOURCE_UPDATE')")
	public String updateResources(@PathVariable Long id,
								  @ModelAttribute ResourcesDto resourcesDto,
								  @RequestParam(value = "selectedRoleIds", required = false) List<Long> selectedRoleIds, // @RequestParam으로 ID 목록 받기
								  RedirectAttributes ra) {
		try {
			resourcesDto.setId(id); // ID를 DTO에 설정
			Resources resources = modelMapper.map(resourcesDto, Resources.class);

			// Role 엔티티 조회
			Set<Role> roles = new HashSet<>();
			if (selectedRoleIds != null && !selectedRoleIds.isEmpty()) {
				roles = selectedRoleIds.stream()
						.map(roleService::getRole)
						.filter(r -> r != null)
						.collect(Collectors.toSet());
			}

			resourcesService.updateResources(resources, roles);

			ra.addFlashAttribute("message", "자원 '" + resources.getResourceName() + "'이 성공적으로 업데이트되었습니다!");
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

	@GetMapping(value = "/delete/{id}")
//	@PreAuthorize("hasRole('ADMIN') or hasAuthority('RESOURCE_DELETE')")
	public String removeResources(@PathVariable Long id, RedirectAttributes ra) throws Exception {
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