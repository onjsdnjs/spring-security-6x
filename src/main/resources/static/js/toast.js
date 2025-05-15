// 이 파일은 home.html 등 필요한 페이지에서 로드해야 합니다.
// 예: <script th:src="@{/js/toast.js}"></script>

/**
 * 간단한 토스트 메시지를 표시합니다.
 * @param {string} message - 표시할 메시지
 * @param {'success' | 'error' | 'info'} type - 메시지 타입 (CSS 클래스에 사용)
 * @param {number} duration - 메시지 표시 시간 (밀리초)
 */
function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container) {
        console.warn('Toast container not found. Using alert instead.');
        alert(`${type.toUpperCase()}: ${message}`);
        return;
    }

    const toast = document.createElement('div');
    toast.className = `p-4 mb-2 rounded-md shadow-lg text-white text-sm toast-${type}`;
    toast.textContent = message;

    // TailwindCSS 클래스 예시 (main.css 또는 style.css에 정의 필요)
    // .toast-success { @apply bg-green-500; }
    // .toast-error { @apply bg-red-500; }
    // .toast-info { @apply bg-blue-500; }

    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('opacity-0', 'transition-opacity', 'duration-500');
        setTimeout(() => {
            toast.remove();
        }, 500); // 애니메이션 시간 후 제거
    }, duration);
}