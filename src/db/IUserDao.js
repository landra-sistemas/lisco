import BaseKnexDao from "./knex/dao/BaseKnexDao.js";

export default class IUserDao extends BaseKnexDao {
    constructor(tableName) {
        super(tableName);

        if (!this.findByUsername) {
            throw new Error("AuthHandler must have 'findByUsername' method");
        }
    }
}
