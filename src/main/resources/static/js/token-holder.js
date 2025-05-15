const TokenMemory = {
    storage: sessionStorage, // 기본은 sessionStorage

    useLocalStorage() {
        this.storage = localStorage;
    },

    useSessionStorage() {
        this.storage = sessionStorage;
    },

    get accessToken() {
        return this.storage.getItem("accessToken");
    },

    set accessToken(token) {
        if (token === null || token === undefined) {
            this.storage.removeItem("accessToken");
        } else {
            this.storage.setItem("accessToken", token);
        }
    },

    get refreshToken() {
        return this.storage.getItem("refreshToken");
    },

    set refreshToken(token) {
        if (token === null || token === undefined) {
            this.storage.removeItem("refreshToken");
        } else {
            this.storage.setItem("refreshToken", token);
        }
    }
};