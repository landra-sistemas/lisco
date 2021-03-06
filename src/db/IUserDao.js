import BaseKnexDao from "./knex/dao/BaseKnexDao";

export default class IUserDao extends BaseKnexDao {
    constructor() {
        super();

        if (!this.findByUsername) {
            throw new Error("AuthHandler must have 'findByUsername' vethod");
        }
    }
}

