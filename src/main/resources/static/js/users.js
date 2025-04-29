document.addEventListener("DOMContentLoaded", function() {
    let useHeader = true; // 기본은 Header 방식

    const headerModeBtn = document.getElementById('headerModeBtn');
    const cookieModeBtn = document.getElementById('cookieModeBtn');
    const usersTableBody = document.querySelector("#usersTable tbody");

    headerModeBtn.addEventListener('click', () => {
        useHeader = true;
        alert("헤더 방식으로 전환되었습니다.");
        loadUsers();
    });

    cookieModeBtn.addEventListener('click', () => {
        useHeader = false;
        alert("쿠키 방식으로 전환되었습니다.");
        loadUsers();
    });

    async function loadUsers() {
        try {
            const accessToken = sessionStorage.getItem('access_token');
            if (!accessToken && useHeader) {
                alert("Access Token이 없습니다. 로그인 해주세요.");
                return;
            }

            const headers = useHeader ? {
                'Authorization': 'Bearer ' + accessToken
            } : {};

            const options = {
                method: 'GET',
                headers: headers,
                credentials: useHeader ? 'same-origin' : 'include' // Header는 same-origin, Cookie는 include
            };

            const res = await fetch('/api/users', options);

            if (res.status === 401 || res.status === 403) {
                alert("인증 실패. 로그인 해주세요.");
                window.location.href = '/loginForm'; // 로그인 페이지로 이동
                return;
            }

            const users = await res.json();
            usersTableBody.innerHTML = ""; // 테이블 초기화

            users.forEach(u => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td style="text-align:center">${u.username}</td>
                    <td style="text-align:center">${u.email}</td>
                    <td style="text-align:center">${u.roles}</td>
                `;
                usersTableBody.appendChild(tr);
            });

        } catch (error) {
            console.error("회원 목록 로드 실패:", error);
            alert("회원 목록을 불러오는 중 오류가 발생했습니다.");
        }
    }

    // 페이지 로딩 후 바로 호출
    loadUsers();
});
