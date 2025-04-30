document.addEventListener("DOMContentLoaded", () => {
    const authMode = localStorage.getItem("authMode");

    let csrfToken = null;
    let csrfHeader = null;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');

    if (csrfTokenMeta && csrfHeaderMeta) {
        csrfToken = csrfTokenMeta.getAttribute("content");
        csrfHeader = csrfHeaderMeta.getAttribute("content");
    }
    async function loadUsers() {
        try {
            const headers = { "Content-Type": "application/json" };

            if (authMode === "header" || authMode === "header_cookie") {
                const accessToken = TokenMemory.accessToken;
                if (accessToken) {
                    headers["Authorization"] = `Bearer ${accessToken}`;
                }
            }

            const res = await fetch("/api/users", {
                method: "GET",
                credentials: "same-origin",
                headers
            });

            if (res.status === 401) {
                console.warn("AccessToken 만료, 리프레시 시도 중...");
                const success = await refreshTokens();
                if (success) return loadUsers();
                window.location.href = "/loginForm";
            } else {
                const users = await res.json();
                renderUsers(users);
            }

        } catch (err) {
            console.error("사용자 목록 로딩 실패:", err);
            alert("오류가 발생했습니다.");
        }
    }

    async function refreshTokens() {
        try {
            const headers = { "Content-Type": "application/json" };

            if (authMode !== "header" && csrfHeader && csrfToken) {
                headers[csrfHeader] = csrfToken;
            }

            const res = await fetch("/api/auth/refresh", {
                method: "POST",
                credentials: "same-origin",
                headers
            });

            if (res.status === 204) {
                console.warn("리프레시 토큰 없음 또는 로그아웃 상태");
                return false;
            }

            if (res.status === 401) {
                console.warn("리프레시 토큰 만료 또는 블랙리스트 상태");
                return false;
            }

            if (!res.ok) return false;

            const data = await res.json();
            console.log("리프레시 성공:", data);

            if (authMode === "header" || authMode === "header_cookie") {
                TokenMemory.accessToken = data.accessToken;
                if (authMode === "header") {
                    TokenMemory.refreshToken = data.refreshToken;
                }
            }

            return true;
        } catch (err) {
            console.error("리프레시 요청 실패:", err);
            return false;
        }
    }

    function renderUsers(users) {
        const tbody = document.querySelector("#usersTable tbody");
        tbody.innerHTML = "";
        users.forEach(user => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td style="text-align:center">${user.username}</td>
                <td style="text-align:center">${user.email}</td>
                <td style="text-align:center">${user.roles}</td>
            `;
            tbody.appendChild(tr);
        });
    }

    loadUsers();
});
