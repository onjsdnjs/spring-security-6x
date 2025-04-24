document.addEventListener("DOMContentLoaded", function() {
    // 1) 바로 /api/users GET 요청
    fetch("/api/users", {
        method:      "GET",
        credentials: "same-origin"  // HTTP-Only 쿠키(accessToken) 자동 포함
    })
        .then(res => {
            if (res.status === 401 || res.status === 403) {
                // 인증 실패 시 로그인 폼으로 리다이렉트
                window.location.href = "/loginForm";
                throw new Error("접근 실패");
            }
            return res.json();
        })
        .then(users => {
            const tbody = document.querySelector("#usersTable tbody");
            tbody.innerHTML = "";  // 초기화
            users.forEach(u => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                <td style="text-align:center">${u.username}</td>
                <td style="text-align:center">${u.email}</td>
                <td style="text-align:center">${u.roles}</td>
            `;
                tbody.appendChild(tr);
            });
        })
        .catch(err => console.error("사용자 목록 로드 실패:", err));
});
