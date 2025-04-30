document.addEventListener("DOMContentLoaded", () => {
    const authMode   = localStorage.getItem("authMode");
    const csrfTokenMeta  = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken  = csrfTokenMeta?.getAttribute("content");
    const csrfHeader = csrfHeaderMeta?.getAttribute("content");

    async function loadUsers() {
        try {
            const headers = {};

            if (authMode === "header" || authMode === "header_cookie") {
                const accessToken = localStorage.getItem("accessToken");
                if (accessToken) {
                    headers["Authorization"] = `Bearer ${accessToken}`;
                }
            }

            const res = await fetch("/api/users", {
                method: "GET",
                credentials: "same-origin",
                headers: headers
            });

            if (res.status === 401) {
                console.warn("AccessToken 만료, 리프레시 시도 중...");
                const refreshSuccess = await refreshTokens();
                if (refreshSuccess) {
                    return loadUsers();
                } else {
                    window.location.href = "/loginForm";
                }
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
            const headers = {
                "Content-Type": "application/json"
            };

            if (authMode !== "header" && csrfHeader && csrfToken) {
                headers[csrfHeader] = csrfToken;
            }

            const res = await fetch("/api/auth/refresh", {
                method: "POST",
                credentials: "same-origin",
                headers
            });

            if (!res.ok) return false;

            const data = await res.json();
            console.log("리프레시 성공:", data);

            if (authMode === "header" || authMode === "header_cookie") {
                localStorage.setItem("accessToken", data.accessToken);
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