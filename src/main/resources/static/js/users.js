document.addEventListener("DOMContentLoaded", function() {
    const token = localStorage.getItem("accessToken");
    if (!token) {
        /* 토큰 없으면 로그인 폼으로 리다이렉트 */
        window.location.href = /*[[@{/loginForm}]]*/ "/loginForm";
        return;
    }
    fetch(/*[[@{/api/users}]]*/ "/api/users", {
        headers: {
            /* JWT 토큰은 보통 "Bearer " 접두사를 붙여야 Security 필터에서 읽힙니다 */
            "Authorization": token
        }
    })
        .then(res => {
            if (res.status === 401) {
                window.location.href = /*[[@{/loginForm}]]*/ "/loginForm";
                throw new Error("인증 실패");
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