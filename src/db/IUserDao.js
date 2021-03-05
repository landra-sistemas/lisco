import BaseKnexDao from "./knex";

export default class IUserDao extends BaseKnexDao{
    constructor() {
        if (!this.findByUsername) {
            throw new Error("AuthHandler must have 'findByUsername' vethod");
        }
    }
}

