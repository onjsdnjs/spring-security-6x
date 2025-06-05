package io.springsecurity.springsecurity6x.admin.controller; // 패키지명 변경: io.springsecurity.springsecurity6x.controller 로 변경 권장

import io.springsecurity.springsecurity6x.admin.service.GroupService;
import io.springsecurity.springsecurity6x.admin.service.RoleService;
import io.springsecurity.springsecurity6x.admin.service.UserManagementService;
import io.springsecurity.springsecurity6x.domain.dto.UserDto;
import io.springsecurity.springsecurity6x.entity.Group;
import io.springsecurity.springsecurity6x.entity.Role;
import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Controller
@RequestMapping("/admin/users") // 공통 경로 설정
@RequiredArgsConstructor
public class UserManagementController {

	private final UserManagementService userManagementService;
	private final RoleService roleService; // 기존에 RoleService 주입받음
	private final GroupService groupService; // GroupService 주입

	@GetMapping
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('USER_READ')") // 권한 설정 예시
	public String getUsers(Model model) {
		List<Users> users = userManagementService.getUsers(); // Users 엔티티 반환
		model.addAttribute("users", users); // Model에 Users 엔티티 리스트 그대로 전달
		return "admin/users";
	}

	@PostMapping
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('USER_UPDATE')") // 권한 설정 예시
	public String modifyUser(@ModelAttribute("user") UserDto userDto, RedirectAttributes ra) { // UserDto 사용
		try {
			userManagementService.modifyUser(userDto);
			ra.addFlashAttribute("message", "사용자 '" + userDto.getUsername() + "' 정보가 성공적으로 수정되었습니다!");
			log.info("User {} modified.", userDto.getUsername());
		} catch (IllegalArgumentException e) {
			ra.addFlashAttribute("errorMessage", e.getMessage());
			log.warn("Failed to modify user {}: {}", userDto.getUsername(), e.getMessage());
		} catch (Exception e) {
			ra.addFlashAttribute("errorMessage", "사용자 수정 중 알 수 없는 오류 발생: " + e.getMessage());
			log.error("Error modifying user {}", userDto.getUsername(), e);
		}
		return "redirect:/admin/users";
	}

	@GetMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('USER_READ')") // 권한 설정 예시
	public String getUser(@PathVariable Long id, Model model) { // Long 타입으로 변경
		UserDto userDto = userManagementService.getUser(id); // UserDto 반환
		List<Role> roleList = roleService.getRolesWithoutExpression(); // 역할 목록 (isExpression이 'N'인 역할)
		List<Group> groupList = groupService.getAllGroups(); // 모든 그룹 목록

		// UserDto에 담긴 selectedGroupIds를 템플릿으로 전달
		List<Long> selectedGroupIds = userDto.getSelectedGroupIds();
		if (selectedGroupIds == null) {
			selectedGroupIds = List.of(); // null 방지
		}

		// MFA 팩터 목록 (UI 드롭다운용)
		List<String> allMfaFactors = Arrays.stream(AuthType.values())
				.filter(type -> type != AuthType.FORM && type != AuthType.REST && type != AuthType.PRIMARY && type != AuthType.MFA)
				.map(AuthType::name)
				.collect(Collectors.toList());


		model.addAttribute("user", userDto);
		model.addAttribute("roleList", roleList); // 이 목록은 Role-Permission 관계에서 참고용
		model.addAttribute("groupList", groupList); // 그룹 목록
		model.addAttribute("selectedGroupIds", selectedGroupIds); // 사용자에게 할당된 그룹 ID 목록
		model.addAttribute("allMfaFactors", allMfaFactors); // 모든 MFA 팩터 타입 (드롭다운 옵션)

		return "admin/userdetails";
	}

	@GetMapping("/delete/{id}")
	@PreAuthorize("hasRole('ADMIN') or hasAuthority('USER_DELETE')") // 권한 설정 예시
	public String removeUser(@PathVariable Long id, RedirectAttributes ra) { // Long 타입으로 변경
		try {
			userManagementService.deleteUser(id);
			ra.addFlashAttribute("message", "사용자 (ID: " + id + ")가 성공적으로 삭제되었습니다!");
			log.info("User ID {} deleted.", id);
		} catch (Exception e) {
			ra.addFlashAttribute("errorMessage", "사용자 삭제 중 오류 발생: " + e.getMessage());
			log.error("Error deleting user ID: {}", id, e);
		}
		return "redirect:/admin/users";
	}
}