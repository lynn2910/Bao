import {defineStore} from "pinia";

interface State {
    firstName: String,
    lastName: String,
    userId: String
}

export const useAuthUserStore = defineStore('test', {
    state: (): State => ({
        firstName: '',
        lastName: '',
        userId: ''
    }),
    getters: {
        fullName: (state) => `${state.firstName} ${state.lastName}`,
        loggedIn: (state) => state.userId !== null,
    },
    actions: {}
})