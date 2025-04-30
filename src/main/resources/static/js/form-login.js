document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("loginForm");
    if (!form) return;

    const authMode = localStorage.getItem("authMode");
    let csrfToken = null;
    let csrfHeader = null;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');

    if (csrfTokenMeta && csrfHeaderMeta) {
        csrfToken = csrfTokenMeta.getAttribute("content");
        csrfHeader = csrfHeaderMeta.getAttribute("content");
    }

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const data = {
            username: form.username.value,
            password: form.password.value
        };

        const headers = {
            "Content-Type": "application/json",
            "X-Device-Id": generateDeviceId()
        };

        if (authMode !== "header" && csrfHeader && csrfToken) {
            headers[csrfHeader] = csrfToken;
        }

        try {
            const res = await fetch("/api/auth/login", {
                method: "POST",
                credentials: "same-origin",
                headers,
                body: JSON.stringify(data)
            });

            if (!res.ok) {
                const error = await res.json().catch(() => null);
                alert("로그인 실패: " + (error?.message || res.statusText));
                return;
            }

            const result = await res.json();
            console.log("로그인 성공:", result);

            if (authMode === "header") {
                // access, refresh 모두 런타임 메모리에 저장
                TokenMemory.accessToken = result.accessToken;
                TokenMemory.refreshToken = result.refreshToken;
            } else if (authMode === "header_cookie") {
                TokenMemory.accessToken = result.accessToken;
            }

            window.location.href = "/";

        } catch (err) {
            console.error("로그인 요청 오류:", err);
            alert("로그인 중 오류가 발생했습니다.");
        }
    });
    function generateDeviceId() {
        let deviceId = localStorage.getItem("deviceId");
        if (!deviceId) {
            deviceId = crypto.randomUUID();
            localStorage.setItem("deviceId", deviceId);
        }
        return deviceId;
    }
});