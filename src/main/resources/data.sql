-- data.sql (PostgreSQL, auth 스키마 기준)

-- 1. 사용자 (Users)
-- 'admin@example.com': ADMIN 역할 (그룹 통해 부여)
-- 'user@example.com': USER 역할 (그룹 통해 부여)
-- 비밀번호는 '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K' (즉, '1234'의 bcrypt 인코딩)
INSERT INTO USERS (username, password, name, roles, age, mfa_enabled, registered_mfa_factors) VALUES
                                                                                                       ('admin@example.com', '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '관리자', 'ADMIN', 30, true, 'OTT,PASSKEY'),
                                                                                                       ('user@example.com', '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '일반사용자', 'USER', 25, false, 'OTT');

-- 2. 역할 (Role)
INSERT INTO ROLE (role_id, role_name, role_desc, is_expression) VALUES
                                                                         (1, 'ADMIN', '시스템 관리자 역할', 'N'),
                                                                         (2, 'MANAGER', '매니저 역할', 'N'),
                                                                         (3, 'USER', '일반 사용자 역할', 'N');

-- 3. 권한 (Permission)
INSERT INTO PERMISSION (permission_id, permission_name, description, target_type, action_type) VALUES
                                                                                                        (1, 'PERMISSION_READ', '권한 정보 읽기', 'PERMISSION', 'READ'),
                                                                                                        (2, 'PERMISSION_CREATE', '권한 정보 생성', 'PERMISSION', 'CREATE'),
                                                                                                        (3, 'PERMISSION_UPDATE', '권한 정보 수정', 'PERMISSION', 'UPDATE'),
                                                                                                        (4, 'PERMISSION_DELETE', '권한 정보 삭제', 'PERMISSION', 'DELETE'),
                                                                                                        (5, 'DOCUMENT_READ', '문서 읽기 권한', 'DOCUMENT', 'READ'),
                                                                                                        (6, 'DOCUMENT_WRITE', '문서 쓰기 권한', 'DOCUMENT', 'WRITE'),
                                                                                                        (7, 'DOCUMENT_DELETE', '문서 삭제 권한', 'DOCUMENT', 'DELETE'),
                                                                                                        (8, 'BOARD_CREATE', '게시판 글쓰기 권한', 'BOARD', 'CREATE'),
                                                                                                        (9, 'METHOD_RESOURCE_READ', '메서드 리소스 읽기', 'METHOD_RESOURCE', 'READ'),
                                                                                                        (10, 'METHOD_RESOURCE_CREATE', '메서드 리소스 생성', 'METHOD_RESOURCE', 'CREATE'),
                                                                                                        (11, 'METHOD_RESOURCE_UPDATE', '메서드 리소스 수정', 'METHOD_RESOURCE', 'UPDATE'),
                                                                                                        (12, 'METHOD_RESOURCE_DELETE', '메서드 리소스 삭제', 'METHOD_RESOURCE', 'DELETE'),
                                                                                                        (13, 'USER_READ', '사용자 정보 읽기', 'USER', 'READ'), -- UserManagementController의 getUsers, getUser에 대한 권한
                                                                                                        (14, 'USER_UPDATE', '사용자 정보 수정', 'USER', 'UPDATE'),
                                                                                                        (15, 'USER_DELETE', '사용자 정보 삭제', 'USER', 'DELETE'),
                                                                                                        (16, 'GROUP_READ', '그룹 정보 읽기', 'GROUP', 'READ'),
                                                                                                        (17, 'GROUP_CREATE', '그룹 정보 생성', 'GROUP', 'CREATE'),
                                                                                                        (18, 'GROUP_UPDATE', '그룹 정보 수정', 'GROUP', 'UPDATE'),
                                                                                                        (19, 'GROUP_DELETE', '그룹 정보 삭제', 'GROUP', 'DELETE'),
                                                                                                        (20, 'RESOURCE_READ', '자원 정보 읽기', 'RESOURCE', 'READ'),
                                                                                                        (21, 'RESOURCE_CREATE', '자원 정보 생성', 'RESOURCE', 'CREATE'),
                                                                                                        (22, 'RESOURCE_UPDATE', '자원 정보 수정', 'RESOURCE', 'UPDATE'),
                                                                                                        (23, 'RESOURCE_DELETE', '자원 정보 삭제', 'RESOURCE', 'DELETE'),
                                                                                                        (24, 'ROLE_READ', '역할 정보 읽기', 'ROLE', 'READ'),
                                                                                                        (25, 'ROLE_CREATE', '역할 정보 생성', 'ROLE', 'CREATE'),
                                                                                                        (26, 'ROLE_UPDATE', '역할 정보 수정', 'ROLE', 'UPDATE'),
                                                                                                        (27, 'ROLE_DELETE', '역할 정보 삭제', 'ROLE', 'DELETE'),
                                                                                                        (28, 'ROLE_HIERARCHY_READ', '역할 계층 읽기', 'ROLE_HIERARCHY', 'READ'),
                                                                                                        (29, 'ROLE_HIERARCHY_CREATE', '역할 계층 생성', 'ROLE_HIERARCHY', 'CREATE'),
                                                                                                        (30, 'ROLE_HIERARCHY_UPDATE', '역할 계층 수정', 'ROLE_HIERARCHY', 'UPDATE'),
                                                                                                        (31, 'ROLE_HIERARCHY_DELETE', '역할 계층 삭제', 'ROLE_HIERARCHY', 'DELETE'),
                                                                                                        (32, 'ROLE_HIERARCHY_ACTIVATE', '역할 계층 활성화', 'ROLE_HIERARCHY', 'ACTIVATE');


-- 4. 그룹 (APP_GROUP)
INSERT INTO APP_GROUP (group_id, group_name, description) VALUES
                                                                   (1, 'ADMIN_GROUP', '시스템 관리자 그룹'),
                                                                   (2, 'DEVELOPER_GROUP', '개발자 그룹 (매니저 역할)'),
                                                                   (3, 'USER_GROUP', '일반 사용자 그룹');

-- 5. User-Group 관계 (USER_GROUPS)
INSERT INTO USER_GROUPS (user_id, group_id) VALUES
                                                     ((SELECT id FROM USERS WHERE username = 'admin@example.com'), (SELECT group_id FROM APP_GROUP WHERE group_name = 'ADMIN_GROUP')),
                                                     ((SELECT id FROM USERS WHERE username = 'admin@example.com'), (SELECT group_id FROM APP_GROUP WHERE group_name = 'DEVELOPER_GROUP')), -- admin은 개발자 그룹에도 속함
                                                     ((SELECT id FROM USERS WHERE username = 'user@example.com'), (SELECT group_id FROM APP_GROUP WHERE group_name = 'USER_GROUP'));

-- 6. Group-Role 관계 (GROUP_ROLES)
INSERT INTO GROUP_ROLES (group_id, role_id) VALUES
                                                     ((SELECT group_id FROM APP_GROUP WHERE group_name = 'ADMIN_GROUP'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                     ((SELECT group_id FROM APP_GROUP WHERE group_name = 'DEVELOPER_GROUP'), (SELECT role_id FROM ROLE WHERE role_name = 'MANAGER')),
                                                     ((SELECT group_id FROM APP_GROUP WHERE group_name = 'USER_GROUP'), (SELECT role_id FROM ROLE WHERE role_name = 'USER'));


-- 7. Role-Permission 관계 (ROLE_PERMISSIONS)
-- ADMIN 역할에 모든 관리 관련 권한 부여
INSERT INTO ROLE_PERMISSIONS (role_id, permission_id) VALUES
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'PERMISSION_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'PERMISSION_CREATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'PERMISSION_UPDATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'PERMISSION_DELETE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_WRITE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_DELETE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'BOARD_CREATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'METHOD_RESOURCE_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'METHOD_RESOURCE_CREATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'METHOD_RESOURCE_UPDATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'METHOD_RESOURCE_DELETE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'USER_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'USER_UPDATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'USER_DELETE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'GROUP_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'GROUP_CREATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'GROUP_UPDATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'GROUP_DELETE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'RESOURCE_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'RESOURCE_CREATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'RESOURCE_UPDATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'RESOURCE_DELETE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_CREATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_UPDATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_DELETE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_HIERARCHY_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_HIERARCHY_CREATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_HIERARCHY_UPDATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_HIERARCHY_DELETE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_HIERARCHY_ACTIVATE'));


-- MANAGER 역할에 특정 권한 부여 (예시)
INSERT INTO ROLE_PERMISSIONS (role_id, permission_id) VALUES
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'MANAGER'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'USER_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'MANAGER'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'MANAGER'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_WRITE'));

-- USER 역할에 기본 권한 부여 (예시)
INSERT INTO ROLE_PERMISSIONS (role_id, permission_id) VALUES
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'USER'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'USER'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'BOARD_CREATE'));


-- 8. 자원 (RESOURCES) - URL 기반 인가
INSERT INTO RESOURCES (resource_id, resource_name, http_method, order_num, resource_type) VALUES
                                                                                                   (1, '/admin/**', 'ALL', 10, 'url'),
                                                                                                   (2, '/users', 'GET', 20, 'url'),
                                                                                                   (3, '/admin/permissions/**', 'ALL', 30, 'url'), -- 관리자 UI에 맞게 추가
                                                                                                   (4, '/admin/roles/**', 'ALL', 40, 'url'),
                                                                                                   (5, '/admin/users/**', 'ALL', 50, 'url'),
                                                                                                   (6, '/admin/groups/**', 'ALL', 60, 'url'),
                                                                                                   (7, '/admin/method-resources/**', 'ALL', 70, 'url'),
                                                                                                   (8, '/admin/role-hierarchies/**', 'ALL', 80, 'url'); -- 새로 추가


-- 9. Resources-Role 관계 (RESOURCES_ROLES)
INSERT INTO RESOURCES_ROLES (resource_id, role_id) VALUES
                                                            ((SELECT resource_id FROM RESOURCES WHERE resource_name = '/admin/**'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                            ((SELECT resource_id FROM RESOURCES WHERE resource_name = '/users'), (SELECT role_id FROM ROLE WHERE role_name = 'USER')),
                                                            ((SELECT resource_id FROM RESOURCES WHERE resource_name = '/admin/permissions/**'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                            ((SELECT resource_id FROM RESOURCES WHERE resource_name = '/admin/roles/**'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                            ((SELECT resource_id FROM RESOURCES WHERE resource_name = '/admin/users/**'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                            ((SELECT resource_id FROM RESOURCES WHERE resource_name = '/admin/groups/**'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                            ((SELECT resource_id FROM RESOURCES WHERE resource_name = '/admin/method-resources/**'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                            ((SELECT resource_id FROM RESOURCES WHERE resource_name = '/admin/role-hierarchies/**'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'));


-- 10. 메서드 자원 (METHOD_RESOURCES) - 동적 메서드 인가
-- io.springsecurity.springsecurity6x.service.DocumentService 클래스에 대한 메서드
INSERT INTO METHOD_RESOURCES (method_resource_id, class_name, method_name, access_expression, order_num, http_method) VALUES
                                                                                                                               (1, 'io.springsecurity.springsecurity6x.service.DocumentService', 'readDocument', 'hasPermission(#id, ''DOCUMENT'', ''READ'')', 100, 'GET'),
                                                                                                                               (2, 'io.springsecurity.springsecurity6x.service.DocumentService', 'updateDocumentContent', 'hasPermission(#id, ''DOCUMENT'', ''WRITE'')', 110, 'POST'),
                                                                                                                               (3, 'io.springsecurity.springsecurity6x.service.DocumentService', 'deleteDocument', 'hasPermission(#id, ''DOCUMENT'', ''DELETE'')', 120, 'DELETE'),
-- UserManagementService의 메서드도 동적 인가 대상으로 추가 (UI 컨트롤러 접근 권한과 연동)
                                                                                                                               (4, 'io.springsecurity.springsecurity6x.admin.service.impl.UserManagementServiceImpl', 'getUsers', 'hasAuthority(''USER_READ'')', 10, 'GET'),
                                                                                                                               (5, 'io.springsecurity.springsecurity6x.admin.service.impl.UserManagementServiceImpl', 'getUser', 'hasAuthority(''USER_READ'')', 20, 'GET'),
                                                                                                                               (6, 'io.springsecurity.springsecurity6x.admin.service.impl.UserManagementServiceImpl', 'modifyUser', 'hasAuthority(''USER_UPDATE'')', 30, 'POST'),
                                                                                                                               (7, 'io.springsecurity.springsecurity6x.admin.service.impl.UserManagementServiceImpl', 'deleteUser', 'hasAuthority(''USER_DELETE'')', 40, 'DELETE'),
-- RoleService의 메서드
                                                                                                                               (8, 'io.springsecurity.springsecurity6x.service.RoleService', 'getRoles', 'hasAuthority(''ROLE_READ'')', 50, 'GET'),
                                                                                                                               (9, 'io.springsecurity.springsecurity6x.service.RoleService', 'getRole', 'hasAuthority(''ROLE_READ'')', 60, 'GET'),
                                                                                                                               (10, 'io.springsecurity.springsecurity6x.service.RoleService', 'createRole', 'hasAuthority(''ROLE_CREATE'')', 70, 'POST'),
                                                                                                                               (11, 'io.springsecurity.springsecurity6x.service.RoleService', 'updateRole', 'hasAuthority(''ROLE_UPDATE'')', 80, 'POST'),
                                                                                                                               (12, 'io.springsecurity.springsecurity6x.service.RoleService', 'deleteRole', 'hasAuthority(''ROLE_DELETE'')', 90, 'DELETE'),
-- PermissionService의 메서드
                                                                                                                               (13, 'io.springsecurity.springsecurity6x.service.PermissionService', 'getAllPermissions', 'hasAuthority(''PERMISSION_READ'')', 100, 'GET'),
                                                                                                                               (14, 'io.springsecurity.springsecurity6x.service.PermissionService', 'getPermission', 'hasAuthority(''PERMISSION_READ'')', 110, 'GET'),
                                                                                                                               (15, 'io.springsecurity.springsecurity6x.service.PermissionService', 'createPermission', 'hasAuthority(''PERMISSION_CREATE'')', 120, 'POST'),
                                                                                                                               (16, 'io.springsecurity.springsecurity6x.service.PermissionService', 'updatePermission', 'hasAuthority(''PERMISSION_UPDATE'')', 130, 'POST'),
                                                                                                                               (17, 'io.springsecurity.springsecurity6x.service.PermissionService', 'deletePermission', 'hasAuthority(''PERMISSION_DELETE'')', 140, 'DELETE'),
-- GroupService의 메서드
                                                                                                                               (18, 'io.springsecurity.springsecurity6x.service.GroupService', 'getAllGroups', 'hasAuthority(''GROUP_READ'')', 150, 'GET'),
                                                                                                                               (19, 'io.springsecurity.springsecurity6x.service.GroupService', 'getGroup', 'hasAuthority(''GROUP_READ'')', 160, 'GET'),
                                                                                                                               (20, 'io.springsecurity.springsecurity6x.service.GroupService', 'createGroup', 'hasAuthority(''GROUP_CREATE'')', 170, 'POST'),
                                                                                                                               (21, 'io.springsecurity.springsecurity6x.service.GroupService', 'updateGroup', 'hasAuthority(''GROUP_UPDATE'')', 180, 'POST'),
                                                                                                                               (22, 'io.springsecurity.springsecurity6x.service.GroupService', 'deleteGroup', 'hasAuthority(''GROUP_DELETE'')', 190, 'DELETE'),
-- ResourcesService의 메서드
                                                                                                                               (23, 'io.springsecurity.springsecurity6x.service.ResourcesService', 'getResources', 'hasAuthority(''RESOURCE_READ'')', 200, 'GET'),
                                                                                                                               (24, 'io.springsecurity.springsecurity6x.service.ResourcesService', 'createResources', 'hasAuthority(''RESOURCE_CREATE'')', 210, 'POST'),
                                                                                                                               (25, 'io.springsecurity.springsecurity6x.service.ResourcesService', 'updateResources', 'hasAuthority(''RESOURCE_UPDATE'')', 220, 'POST'),
                                                                                                                               (26, 'io.springsecurity.springsecurity6x.service.ResourcesService', 'deleteResources', 'hasAuthority(''RESOURCE_DELETE'')', 230, 'DELETE'),
-- RoleHierarchyService의 메서드
                                                                                                                               (27, 'io.springsecurity.springsecurity6x.service.RoleHierarchyService', 'getAllRoleHierarchies', 'hasAuthority(''ROLE_HIERARCHY_READ'')', 240, 'GET'),
                                                                                                                               (28, 'io.springsecurity.springsecurity6x.service.RoleHierarchyService', 'getRoleHierarchy', 'hasAuthority(''ROLE_HIERARCHY_READ'')', 250, 'GET'),
                                                                                                                               (29, 'io.springsecurity.springsecurity6x.service.RoleHierarchyService', 'createRoleHierarchy', 'hasAuthority(''ROLE_HIERARCHY_CREATE'')', 260, 'POST'),
                                                                                                                               (30, 'io.springsecurity.springsecurity6x.service.RoleHierarchyService', 'updateRoleHierarchy', 'hasAuthority(''ROLE_HIERARCHY_UPDATE'')', 270, 'POST'),
                                                                                                                               (31, 'io.springsecurity.springsecurity6x.service.RoleHierarchyService', 'deleteRoleHierarchy', 'hasAuthority(''ROLE_HIERARCHY_DELETE'')', 280, 'DELETE'),
                                                                                                                               (32, 'io.springsecurity.springsecurity6x.service.RoleHierarchyService', 'activateRoleHierarchy', 'hasAuthority(''ROLE_HIERARCHY_ACTIVATE'')', 290, 'POST');


-- 11. METHOD_RESOURCE_ROLES (MethodResource <-> Role)
-- 사용자 관리 메서드에 ADMIN 역할 필요 (URL 기반과 동일하게)
INSERT INTO METHOD_RESOURCE_ROLES (method_resource_id, role_id) VALUES
                                                                         ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.admin.service.impl.UserManagementServiceImpl' AND method_name = 'getUsers'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                                         ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.admin.service.impl.UserManagementServiceImpl' AND method_name = 'getUser'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                                         ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.admin.service.impl.UserManagementServiceImpl' AND method_name = 'modifyUser'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                                         ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.admin.service.impl.UserManagementServiceImpl' AND method_name = 'deleteUser'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),

-- 문서 서비스 메서드에 ADMIN 역할 필요
                                                                         ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.DocumentService' AND method_name = 'readDocument'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                                         ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.DocumentService' AND method_name = 'updateDocumentContent'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                                         ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.DocumentService' AND method_name = 'deleteDocument'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'));


-- 12. METHOD_RESOURCE_PERMISSIONS (MethodResource <-> Permission)
-- 동적 SpEL 표현식 평가를 위해 METHOD_RESOURCES에 이미 SpEL이 저장되어 있으므로,
-- 여기서는 추가적인 세밀한 권한 매핑을 하는 경우에만 사용합니다.
-- 예시: readDocument에 DOCUMENT_READ 권한이 필요하다고 명시
INSERT INTO METHOD_RESOURCE_PERMISSIONS (method_resource_id, permission_id) VALUES
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.DocumentService' AND method_name = 'readDocument'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_READ')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.DocumentService' AND method_name = 'updateDocumentContent'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_WRITE')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.DocumentService' AND method_name = 'deleteDocument'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_DELETE'));

-- User Management Service 메서드에 대한 Permission 매핑
INSERT INTO METHOD_RESOURCE_PERMISSIONS (method_resource_id, permission_id) VALUES
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.admin.service.impl.UserManagementServiceImpl' AND method_name = 'getUsers'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'USER_READ')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.admin.service.impl.UserManagementServiceImpl' AND method_name = 'getUser'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'USER_READ')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.admin.service.impl.UserManagementServiceImpl' AND method_name = 'modifyUser'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'USER_UPDATE')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.admin.service.impl.UserManagementServiceImpl' AND method_name = 'deleteUser'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'USER_DELETE'));

-- Role Service 메서드에 대한 Permission 매핑
INSERT INTO METHOD_RESOURCE_PERMISSIONS (method_resource_id, permission_id) VALUES
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.RoleService' AND method_name = 'getRoles'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_READ')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.RoleService' AND method_name = 'getRole'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_READ')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.RoleService' AND method_name = 'createRole'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_CREATE')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.RoleService' AND method_name = 'updateRole'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_UPDATE')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.RoleService' AND method_name = 'deleteRole'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_DELETE'));

-- Permission Service 메서드에 대한 Permission 매핑
INSERT INTO METHOD_RESOURCE_PERMISSIONS (method_resource_id, permission_id) VALUES
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.PermissionService' AND method_name = 'getAllPermissions'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'PERMISSION_READ')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.PermissionService' AND method_name = 'getPermission'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'PERMISSION_READ')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.PermissionService' AND method_name = 'createPermission'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'PERMISSION_CREATE')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.PermissionService' AND method_name = 'updatePermission'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'PERMISSION_UPDATE')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.PermissionService' AND method_name = 'deletePermission'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'PERMISSION_DELETE'));

-- Group Service 메서드에 대한 Permission 매핑
INSERT INTO METHOD_RESOURCE_PERMISSIONS (method_resource_id, permission_id) VALUES
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.GroupService' AND method_name = 'getAllGroups'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'GROUP_READ')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.GroupService' AND method_name = 'getGroup'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'GROUP_READ')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.GroupService' AND method_name = 'createGroup'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'GROUP_CREATE')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.GroupService' AND method_name = 'updateGroup'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'GROUP_UPDATE')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.GroupService' AND method_name = 'deleteGroup'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'GROUP_DELETE'));

-- Resources Service 메서드에 대한 Permission 매핑
INSERT INTO METHOD_RESOURCE_PERMISSIONS (method_resource_id, permission_id) VALUES
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.ResourcesService' AND method_name = 'getResources'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'RESOURCE_READ')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.ResourcesService' AND method_name = 'createResources'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'RESOURCE_CREATE')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.ResourcesService' AND method_name = 'updateResources'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'RESOURCE_UPDATE')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.ResourcesService' AND method_name = 'deleteResources'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'RESOURCE_DELETE'));

-- RoleHierarchy Service 메서드에 대한 Permission 매핑
INSERT INTO METHOD_RESOURCE_PERMISSIONS (method_resource_id, permission_id) VALUES
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.RoleHierarchyService' AND method_name = 'getAllRoleHierarchies'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_HIERARCHY_READ')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.RoleHierarchyService' AND method_name = 'getRoleHierarchy'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_HIERARCHY_READ')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.RoleHierarchyService' AND method_name = 'createRoleHierarchy'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_HIERARCHY_CREATE')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.RoleHierarchyService' AND method_name = 'updateRoleHierarchy'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_HIERARCHY_UPDATE')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.RoleHierarchyService' AND method_name = 'deleteRoleHierarchy'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_HIERARCHY_DELETE')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.RoleHierarchyService' AND method_name = 'activateRoleHierarchy'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'ROLE_HIERARCHY_ACTIVATE'));


-- 13. 문서 (DOCUMENT)
INSERT INTO DOCUMENT (document_id, title, content, owner_username, created_at) VALUES
                                                                                        (1, '관리자 문서 1', '이 문서는 관리자만 볼 수 있는 기밀 문서입니다.', 'admin@example.com', NOW()),
                                                                                        (2, '사용자 문서 1', '이 문서는 일반 사용자만 수정할 수 있는 문서입니다.', 'user@example.com', NOW()),
                                                                                        (3, '공개 문서', '이 문서는 모든 사용자가 읽을 수 있는 공개 문서입니다.', 'guest@example.com', NOW());