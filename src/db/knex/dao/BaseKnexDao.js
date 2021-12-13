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

    async loadFilteredDataWithRelations(filters, start, limit, relationParams, selectQuery) {
        let sorts = [];

        if (filters.sort) {
            sorts = KnexFilterParser.parseSort(filters.sort);
        } else {
            sorts = 1;
        }
        let connect = KnexConnector$1.connection
            .select(KnexConnector$1.connection.raw(selectQuery))
            .from(this.tableName)
            .where((builder) =>
                KnexFilterParser.parseFilters(builder, lodash__default['default'].omit(filters, ["sort", "start", "limit"]))
            )

        if (relationParams) {
            if (Array.isArray(relationParams)) {
                relationParams.forEach(element => {
                    let typeInner = element.type
                    let tabletoJoinInner = element.tabletoJoin
                    let column1Inner = element.column1
                    let column2Inner = element.column2
                    connect = connect.joinRaw(typeInner + " " + tabletoJoinInner + " ON " + column1Inner + " = " + column2Inner)
                });
            } else {
                let type = relationParams.type
                let tabletoJoin = relationParams.tabletoJoin
                let column1 = relationParams.column1
                let column2 = relationParams.column2
                connect = connect.joinRaw(type + " " + tabletoJoin + " ON " + column1 + " = " + column2)
            }
        }

        return connect.orderByRaw(sorts).limit(limit).offset(start);


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
