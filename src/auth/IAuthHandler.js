export default class IAuthHandler {
    constructor() {
        if (!this.check) {
            throw new Error("AuthHandler must have 'check' vethod");
        }
        if (!this.validate) {
            throw new Error("AuthHandler must have 'validate' vethod");
        }
        // logout method is optional
    }
}

