-- data.sql (PostgreSQL, auth 스키마 기준)

-- 1. 사용자 (Users)
-- 'admin' 사용자는 ROLE_ADMIN과 ROLE_USER 역할을 모두 가질 예정
-- 'user' 사용자는 ROLE_USER 역할만 가질 예정
-- 비밀번호는 `{noop}1234` (실제로는 PasswordEncoder로 인코딩 필요)
INSERT INTO USERS (username, password, name, roles, age, mfa_enabled, registered_mfa_factors) VALUES
                                                                                                       ('admin@example.com', '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '관리자', 'ADMIN', 30, true, 'OTT,PASSKEY'), -- bcrypt 인코딩된 '1234'
                                                                                                       ('user@example.com', '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '일반사용자', 'USER', 25, false, 'OTT');

-- 2. 역할 (Role)
INSERT INTO ROLE (role_name, role_desc, is_expression) VALUES
                                                                ('ADMIN', '시스템 관리자 역할', 'N'),
                                                                ('MANAGER', '매니저 역할', 'N'),
                                                                ('USER', '일반 사용자 역할', 'N');

-- 3. 권한 (Permission)
INSERT INTO PERMISSION (permission_name, description, target_type, action_type) VALUES
                                                                                         ('PERMISSION_READ', '권한 정보 읽기', 'PERMISSION', 'READ'),
                                                                                         ('PERMISSION_CREATE', '권한 정보 생성', 'PERMISSION', 'CREATE'),
                                                                                         ('PERMISSION_UPDATE', '권한 정보 수정', 'PERMISSION', 'UPDATE'),
                                                                                         ('PERMISSION_DELETE', '권한 정보 삭제', 'PERMISSION', 'DELETE'),
                                                                                         ('DOCUMENT_READ', '문서 읽기 권한', 'DOCUMENT', 'READ'),
                                                                                         ('DOCUMENT_WRITE', '문서 쓰기 권한', 'DOCUMENT', 'WRITE'),
                                                                                         ('BOARD_CREATE', '게시판 글쓰기 권한', 'BOARD', 'CREATE'),
                                                                                         ('METHOD_RESOURCE_READ', '메서드 리소스 읽기', 'METHOD_RESOURCE', 'READ'),
                                                                                         ('METHOD_RESOURCE_CREATE', '메서드 리소스 생성', 'METHOD_RESOURCE', 'CREATE'),
                                                                                         ('METHOD_RESOURCE_UPDATE', '메서드 리소스 수정', 'METHOD_RESOURCE', 'UPDATE'),
                                                                                         ('METHOD_RESOURCE_DELETE', '메서드 리소스 삭제', 'METHOD_RESOURCE', 'DELETE');

-- 4. 그룹 (APP_GROUP)
INSERT INTO APP_GROUP (group_name, description) VALUES
                                                         ('ADMIN_GROUP', '관리자 그룹'),
                                                         ('DEVELOPER_GROUP', '개발자 그룹'),
                                                         ('USER_GROUP', '일반 사용자 그룹');


-- 5. User-Group 관계 (USER_GROUPS)
INSERT INTO USER_GROUPS (user_id, group_id) VALUES
                                                     ((SELECT id FROM USERS WHERE username = 'admin@example.com'), (SELECT group_id FROM APP_GROUP WHERE group_name = 'ADMIN_GROUP')),
                                                     ((SELECT id FROM USERS WHERE username = 'admin@example.com'), (SELECT group_id FROM APP_GROUP WHERE group_name = 'DEVELOPER_GROUP')),
                                                     ((SELECT id FROM USERS WHERE username = 'user@example.com'), (SELECT group_id FROM APP_GROUP WHERE group_name = 'USER_GROUP'));

-- 6. Group-Role 관계 (GROUP_ROLES)
INSERT INTO GROUP_ROLES (group_id, role_id) VALUES
                                                     ((SELECT group_id FROM APP_GROUP WHERE group_name = 'ADMIN_GROUP'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                     ((SELECT group_id FROM APP_GROUP WHERE group_name = 'DEVELOPER_GROUP'), (SELECT role_id FROM ROLE WHERE role_name = 'MANAGER')),
                                                     ((SELECT group_id FROM APP_GROUP WHERE group_name = 'USER_GROUP'), (SELECT role_id FROM ROLE WHERE role_name = 'USER'));


-- 7. Role-Permission 관계 (ROLE_PERMISSIONS)
-- ADMIN 역할에 모든 권한 부여 (예시)
INSERT INTO ROLE_PERMISSIONS (role_id, permission_id) VALUES
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'PERMISSION_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'PERMISSION_CREATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'PERMISSION_UPDATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'PERMISSION_DELETE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_WRITE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'BOARD_CREATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'METHOD_RESOURCE_READ')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'METHOD_RESOURCE_CREATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'METHOD_RESOURCE_UPDATE')),
                                                               ((SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'METHOD_RESOURCE_DELETE'));

-- USER 역할에 문서 읽기 권한 부여 (예시)
INSERT INTO ROLE_PERMISSIONS (role_id, permission_id) VALUES
    ((SELECT role_id FROM ROLE WHERE role_name = 'USER'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_READ'));


-- 8. 자원 (RESOURCES) - URL 기반 인가 (기존 역할 유지)
INSERT INTO RESOURCES (resource_name, http_method, order_num, resource_type) VALUES
                                                                                      ('/admin/**', 'ALL', 10, 'url'),
                                                                                      ('/users', 'GET', 20, 'url');

-- 9. Resources-Role 관계 (RESOURCES_ROLES) - 기존 role_resources 대체
INSERT INTO RESOURCES_ROLES (resource_id, role_id) VALUES
                                                            ((SELECT resource_id FROM RESOURCES WHERE resource_name = '/admin/**'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN')),
                                                            ((SELECT resource_id FROM RESOURCES WHERE resource_name = '/users'), (SELECT role_id FROM ROLE WHERE role_name = 'USER'));


-- 10. 메서드 자원 (METHOD_RESOURCES) - 동적 메서드 인가 (예시)
-- com.example.service.DocumentService.readDocument(Long id) 메서드는 DOCUMENT_READ 권한 필요
INSERT INTO METHOD_RESOURCES (class_name, method_name, access_expression, order_num, http_method) VALUES
                                                                                                           ('io.springsecurity.springsecurity6x.service.DocumentService', 'readDocument', 'hasPermission(#id, ''Document'', ''READ'')', 100, 'GET'),
                                                                                                           ('io.springsecurity.springsecurity6x.service.DocumentService', 'updateDocument', 'hasPermission(#id, ''Document'', ''WRITE'')', 110, 'POST');

-- 11. MethodResource-Role 관계 (METHOD_RESOURCE_ROLES)
INSERT INTO METHOD_RESOURCE_ROLES (method_resource_id, role_id) VALUES
                                                                         ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.DocumentService' AND method_name = 'readDocument'), (SELECT role_id FROM ROLE WHERE role_name = 'USER')),
                                                                         ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.DocumentService' AND method_name = 'updateDocument'), (SELECT role_id FROM ROLE WHERE role_name = 'ADMIN'));

-- 12. MethodResource-Permission 관계 (METHOD_RESOURCE_PERMISSIONS)
INSERT INTO METHOD_RESOURCE_PERMISSIONS (method_resource_id, permission_id) VALUES
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.DocumentService' AND method_name = 'readDocument'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_READ')),
                                                                                     ((SELECT method_resource_id FROM METHOD_RESOURCES WHERE class_name = 'io.springsecurity.springsecurity6x.service.DocumentService' AND method_name = 'updateDocument'), (SELECT permission_id FROM PERMISSION WHERE permission_name = 'DOCUMENT_WRITE'));