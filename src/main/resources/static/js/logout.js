document.addEventListener("DOMContentLoaded", function() {
    // 본문의 로그아웃 버튼
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", function() {
            localStorage.removeItem("accessToken");
            window.location.href = "/loginForm";
        });
    }

    // 헤더의 로그아웃 링크
    const logoutLink = document.getElementById("logoutLink");
    if (logoutLink) {
        logoutLink.addEventListener("click", function(e) {
            e.preventDefault();
            localStorage.removeItem("accessToken");
            window.location.href = "/loginForm";
        });
    }

    // (선택) 로그인/로그아웃 링크 토글
    const loginLink  = document.getElementById("loginLink");
    if (loginLink) {
        loginLink.style.display = localStorage.getItem("accessToken") ? "none" : "inline-block";
    }
    if (logoutLink) {
        logoutLink.style.display = localStorage.getItem("accessToken") ? "inline-block" : "none";
    }
});