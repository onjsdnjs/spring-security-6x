document.addEventListener("DOMContentLoaded", () => {
    const btn        = document.getElementById("passkeyBtn");
    const csrfToken  = document.querySelector('meta[name="_csrf"]').getAttribute("content");
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute("content");

    btn.addEventListener("click", async () => {
        try {
            const options   = await fetch("/webauthn/assertion/options", {
                method:      "GET",
                credentials: "same-origin"
            }).then(r => r.json());

            const assertion = await navigator.credentials.get({ publicKey: options });
            const res       = await fetch("/login/passkey", {
                method:      "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json",
                    [csrfHeader]:    csrfToken
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
});
