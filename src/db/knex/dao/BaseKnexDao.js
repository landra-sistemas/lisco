import KnexFilterParser from '../filters/KnexFilterParser';
import KnexConnector from '../KnexConnector';

import lodash from 'lodash';

/**
 * Crear un dao con los métodos básicos
 */
export default class BaseKnexDao {

    tableName = "";

    constructor() {

    }


    loadAllData(start, limit) {
        return KnexConnector.connection.select('*').from(this.tableName).limit(limit || 10000).offset(start)
    }

    async loadFilteredData(filters, start, limit) {
        let sorts = 1;
        if (filters.sort) {
            sorts = KnexFilterParser.parseSort(filters.sort);
        }

        return KnexConnector.connection.from(this.tableName).where((builder) => (
            KnexFilterParser.parseFilters(builder, lodash.omit(filters, ['sort', 'start', 'limit']))
        )).orderByRaw(sorts).limit(limit).offset(start);

    }

    async loadFilteredDataWithRelations(filters, start, limit, relation_config) {
        let sorts = [];

        if (filters.sort) {
            sorts = KnexFilterParser.parseSort(filters.sort);
        } else {
            sorts = 1;
        }
        let qry = KnexConnector.connection
            .select(KnexConnector.connection.raw(relation_config.selectQuery))
            .from(this.tableName)
            .groupBy(relation_config.group_by)
            .where((builder) =>
                KnexFilterParser.parseFilters(builder, lodash.omit(filters, ["sort", "start", "limit"]))
            )

        if (relation_config.relation_schema) {
            if (!Array.isArray(relation_config.relation_schema)) {
                relationParams = [relation_config.relation_schema];
            }
            relation_config.relation_schema.forEach(element => {
                qry = qry.joinRaw(element.type + " " + element.with_table + " ON " + element.on_condition)
            });
        }

        return qry.orderByRaw(sorts).limit(limit).offset(start);


    }

    async countFilteredData(filters) {
        let data = await KnexConnector.connection.from(this.tableName).where((builder) => (
            KnexFilterParser.parseFilters(builder, lodash.omit(filters, ['sort', 'start', 'limit']))
        )).count('id', { as: 'total' });

        return data && data[0].total;
    }

    async loadById(objectId) {
        const data = await KnexConnector.connection.from(this.tableName).where('id', objectId);

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
        return KnexConnector.connection.from(this.tableName).where("id", objectId).delete()
    }
}
