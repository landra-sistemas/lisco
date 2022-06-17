import KnexFilterParser from "../filters/KnexFilterParser.js";
import KnexConnector from "../KnexConnector.js";

import lodash from "lodash";

/**
 * Crear un dao con los métodos básicos
 */
export default class BaseKnexDao {
    constructor() {
        this.tableName = "";
    }

    loadAllData(start, limit) {
        return KnexConnector.connection
            .select("*")
            .from(this.tableName)
            .limit(limit || 10000)
            .offset(start);
    }

    async loadFilteredData(filters, start, limit) {
        let sorts = 1;
        if (filters.sort) {
            sorts = KnexFilterParser.parseSort(filters.sort);
        }

        return KnexConnector.connection
            .from(this.tableName)
            .where((builder) => KnexFilterParser.parseFilters(builder, lodash.omit(filters, ["sort", "start", "limit"]), this.tableName))
            .orderByRaw(sorts)
            .limit(limit)
            .offset(start);
    }

    async countFilteredData(filters) {
        let data = await KnexConnector.connection
            .from(this.tableName)
            .where((builder) => KnexFilterParser.parseFilters(builder, lodash.omit(filters, ["sort", "start", "limit"]), this.tableName))
            .count("id", { as: "total" });

        return data && data[0].total;
    }

    async loadById(objectId) {
        const data = await KnexConnector.connection.from(this.tableName).where("id", objectId);

        if (data && data[0]) {
            return data[0];
        }
        return null;
    }

    save(object) {
        return KnexConnector.connection.from(this.tableName).insert(object).returning("*");
    }
    update(objectId, newObject) {
        return KnexConnector.connection.from(this.tableName).where("id", objectId).update(newObject).returning("*");
    }
    async delete(objectId) {
        const existing = await this.loadById(objectId);
        if (!existing) {
            throw "NotFound";
        }
        return KnexConnector.connection.from(this.tableName).where("id", objectId).delete();
    }
}
