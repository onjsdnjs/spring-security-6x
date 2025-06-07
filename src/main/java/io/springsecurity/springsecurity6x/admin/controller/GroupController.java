package io.springsecurity.springsecurity6x.admin.controller;

import io.springsecurity.springsecurity6x.admin.service.GroupService;
import io.springsecurity.springsecurity6x.admin.service.RoleService;
import io.springsecurity.springsecurity6x.domain.dto.GroupDto;
import io.springsecurity.springsecurity6x.entity.Group;
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
import java.util.stream.Collectors;

@Slf4j
@Controller
@RequestMapping("/admin/groups") // 그룹 관리를 위한 공통 경로 설정
@RequiredArgsConstructor
public class GroupController {

    private final GroupService groupService;
    private final RoleService roleService; // RoleService 주입
    private final ModelMapper modelMapper;

    @GetMapping
//    @PreAuthorize("hasRole('ADMIN') or hasAuthority('GROUP_READ')") // 권한 설정 예시
    public String getGroups(Model model) {
        List<Group> groups = groupService.getAllGroups();
        model.addAttribute("groups", groups);
        log.info("Displaying groups list. Total: {}", groups.size());
        return "admin/groups";
    }

    @GetMapping("/register")
//    @PreAuthorize("hasRole('ADMIN') or hasAuthority('GROUP_CREATE')") // 권한 설정 예시
    public String registerGroupForm(Model model) {
        model.addAttribute("group", new GroupDto()); // 빈 DTO 객체 전달
        model.addAttribute("roleList", roleService.getRoles()); // 모든 Role 목록
        model.addAttribute("selectedRoleIds", new HashSet<Long>()); // 선택된 역할 ID 목록 초기화
        log.info("Displaying new group registration form.");
        return "admin/groupdetails";
    }

    @PostMapping
//    @PreAuthorize("hasRole('ADMIN') or hasAuthority('GROUP_CREATE')") // 권한 설정 예시
    public String createGroup(@ModelAttribute("group") GroupDto groupDto,
                              @RequestParam(value = "selectedRoleIds", required = false) List<Long> selectedRoleIds,
                              RedirectAttributes ra) {
        try {
            Group group = modelMapper.map(groupDto, Group.class);
            groupService.createGroup(group, selectedRoleIds); // Service에 selectedRoleIds 전달

            ra.addFlashAttribute("message", "그룹 '" + group.getName() + "'이 성공적으로 생성되었습니다.");
            log.info("Group created: {}", group.getName());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.warn("Failed to create group: {}", e.getMessage());
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "그룹 생성 중 알 수 없는 오류 발생: " + e.getMessage());
            log.error("Error creating group", e);
        }
        return "redirect:/admin/groups";
    }

    @GetMapping("/{id}")
//    @PreAuthorize("hasRole('ADMIN') or hasAuthority('GROUP_READ')") // 권한 설정 예시
    public String getGroupDetails(@PathVariable Long id, Model model) {
        Group group = groupService.getGroup(id)
                .orElseThrow(() -> new IllegalArgumentException("Invalid group ID: " + id));
        GroupDto groupDto = modelMapper.map(group, GroupDto.class);

        // 현재 Group에 할당된 Role들의 ID 목록을 DTO에 설정
        List<Long> selectedRoleIds = group.getGroupRoles().stream()
                .map(gr -> gr.getRole().getId())
                .collect(Collectors.toList());

        model.addAttribute("group", groupDto);
        model.addAttribute("roleList", roleService.getRoles()); // 모든 Role 목록
        model.addAttribute("selectedRoleIds", selectedRoleIds); // 현재 선택된 역할 ID 목록
        log.info("Displaying details for group ID: {}", id);
        return "admin/groupdetails";
    }

    @PostMapping("/{id}/edit")
//    @PreAuthorize("hasRole('ADMIN') or hasAuthority('GROUP_UPDATE')") // 권한 설정 예시
    public String updateGroup(@PathVariable Long id, @ModelAttribute("group") GroupDto groupDto,
                              @RequestParam(value = "selectedRoleIds", required = false) List<Long> selectedRoleIds,
                              RedirectAttributes ra) {
        try {
            groupDto.setId(id); // URL 경로에서 받은 ID를 DTO에 설정
            Group group = modelMapper.map(groupDto, Group.class);
            groupService.updateGroup(group, selectedRoleIds); // Service에 selectedRoleIds 전달

            ra.addFlashAttribute("message", "그룹 '" + group.getName() + "'이 성공적으로 업데이트되었습니다!");
            log.info("Group updated: {}", group.getName());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.warn("Failed to update group: {}", e.getMessage());
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "그룹 업데이트 중 알 수 없는 오류 발생: " + e.getMessage());
            log.error("Error updating group", e);
        }
        return "redirect:/admin/groups";
    }

    @GetMapping("/delete/{id}")
//    @PreAuthorize("hasRole('ADMIN') or hasAuthority('GROUP_DELETE')") // 권한 설정 예시
    public String deleteGroup(@PathVariable Long id, RedirectAttributes ra) {
        try {
            groupService.deleteGroup(id);
            ra.addFlashAttribute("message", "그룹 (ID: " + id + ")이 성공적으로 삭제되었습니다!");
            log.info("Group deleted: ID {}", id);
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "그룹 삭제 중 오류 발생: " + e.getMessage());
            log.error("Error deleting group ID: {}", id, e);
        }
        return "redirect:/admin/groups";
    }
}
