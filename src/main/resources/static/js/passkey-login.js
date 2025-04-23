document.getElementById("passkeyBtn").addEventListener("click", async () => {
    const csrfToken = getCookie("XSRF-TOKEN");
    try {
        const options   = await fetch("/webauthn/assertion/options", {
            credentials: "same-origin"  // 옵션 요청에도 인증 쿠키 포함
        }).then(r => r.json());
        const assertion = await navigator.credentials.get({ publicKey: options });
        const res = await fetch("/login/passkey", {
            method:      "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                "X-XSRF-TOKEN": csrfToken
            },
            body: JSON.stringify(assertion)
        });
        if (res.ok) {
            window.location.href = "/users";
        } else {
            alert("Passkey 인증에 실패했습니다.");
        }
    } catch {
        alert("Passkey 인증 중 오류가 발생했거나 지원되지 않는 브라우저입니다.");
    }
});

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        return parts.pop().split(';').shift();
    }
    return null;
}