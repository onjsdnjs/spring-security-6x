document.addEventListener("DOMContentLoaded", () => {

    // const csrfToken  = document.querySelector('meta[name="_csrf"]').getAttribute("content");
    // const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute("content");

    const headerModeBtn = document.getElementById("headerModeBtn");
    const cookieModeBtn = document.getElementById("cookieModeBtn");

    let useHeaderMode = false;  // 기본은 쿠키 모드

    headerModeBtn.addEventListener("click", () => {
        useHeaderMode = true;
        alert("헤더 방식으로 변경되었습니다.");
    });

    cookieModeBtn.addEventListener("click", () => {
        useHeaderMode = false;
        alert("쿠키 방식으로 변경되었습니다.");
    });

    async function loadUsers() {
        try {
            const headers = {};

            if (useHeaderMode) {
                const accessToken = localStorage.getItem("access_token");
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
                    return loadUsers(); // 토큰 갱신 후 재시도
                } else {
                    alert("세션이 만료되었습니다. 다시 로그인하세요.");
                    window.location.href = "/loginForm";
                }
            }else{
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
            const res = await fetch("/api/auth/refresh", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json",
                    // [csrfHeader]:    csrfToken
                }
            });

            if (!res.ok) {
                console.error("Refresh 실패:", res.status);
                return false;
            }

            const tokens = await res.json();
            console.log("Refresh 성공:", tokens);

            if (useHeaderMode) {
                localStorage.setItem("access_token", tokens.access_token);
            }
            return true;

        } catch (err) {
            console.error("Refresh 요청 실패:", err);
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

    // 페이지 로드 시 자동으로 사용자 목록 조회
    loadUsers();
});
