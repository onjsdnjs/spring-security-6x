document.addEventListener("DOMContentLoaded", function() {
    const accessTokenKey = "accessToken"; // localStorage key
    const refreshEndpoint = "/api/auth/refresh";
    const usersEndpoint = "/api/users";

    let useHeaderMode = false; // 기본은 쿠키 방식

    const headerModeBtn = document.getElementById("headerModeBtn");
    const cookieModeBtn = document.getElementById("cookieModeBtn");

    headerModeBtn.addEventListener("click", () => {
        useHeaderMode = true;
        alert("헤더 방식으로 토큰 전송을 설정했습니다.");
        loadUsers();
    });

    cookieModeBtn.addEventListener("click", () => {
        useHeaderMode = false;
        alert("쿠키 방식으로 토큰 전송을 설정했습니다.");
        loadUsers();
    });

    async function fetchWithToken(url, options = {}) {
        const headers = {
            ...(options.headers || {})
        };

        if (useHeaderMode) {
            const accessToken = localStorage.getItem(accessTokenKey);
            if (!accessToken) {
                redirectToLogin();
                return;
            }
            headers["Authorization"] = `Bearer ${accessToken}`;
        }

        const fetchOptions = {
            ...options,
            headers,
            credentials: "same-origin",
        };

        let response = await fetch(url, fetchOptions);

        if (response.status === 401 || response.status === 403) {
            const refreshed = await attemptRefreshToken();
            if (refreshed) {
                if (useHeaderMode) {
                    const newAccessToken = localStorage.getItem(accessTokenKey);
                    fetchOptions.headers["Authorization"] = `Bearer ${newAccessToken}`;
                }
                response = await fetch(url, fetchOptions);
            } else {
                redirectToLogin();
                return;
            }
        }

        return response;
    }

    async function attemptRefreshToken() {
        try {
            const res = await fetch(refreshEndpoint, {
                method: "POST",
                credentials: "same-origin"
            });

            if (res.ok) {
                const tokens = await res.json();
                if (tokens.accessToken) {
                    localStorage.setItem(accessTokenKey, tokens.accessToken);
                    if (tokens.refreshToken) {
                        localStorage.setItem("refreshToken", tokens.refreshToken);
                    }
                    return true;
                }
            }
        } catch (err) {
            console.error("리프레시 실패:", err);
        }
        return false;
    }

    async function loadUsers() {
        try {
            const res = await fetchWithToken(usersEndpoint, { method: "GET" });

            if (!res || !res.ok) {
                throw new Error("사용자 목록 로드 실패");
            }

            const users = await res.json();
            renderUsers(users);
        } catch (err) {
            console.error("사용자 목록 로드 실패:", err);
            alert("사용자 정보를 가져오는 중 오류가 발생했습니다.");
        }
    }

    function renderUsers(users) {
        const tbody = document.querySelector("#usersTable tbody");
        tbody.innerHTML = "";

        users.forEach(u => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td style="text-align:center">${u.username}</td>
                <td style="text-align:center">${u.email}</td>
                <td style="text-align:center">${u.roles}</td>
            `;
            tbody.appendChild(tr);
        });
    }

    function redirectToLogin() {
        window.location.href = "/loginForm";
    }

    // 최초 진입 시 데이터 로딩
    loadUsers();
});
