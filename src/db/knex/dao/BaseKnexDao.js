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

    async countFilteredData(filters) {
        let data = await KnexConnector.connection.from(this.tableName).where((builder) => (
            KnexFilterParser.parseFilters(builder, lodash.omit(filters, ['sort', 'start', 'limit']))
        )).count('id', { as: 'total' });

        return data && data[0].total;
    }

    async loadById(objectId) {
        return KnexConnector.connection.from(this.tableName).where('id', objectId);
    }

    save(object) {
        return KnexConnector.connection.from(this.tableName).insert(object);
    }
    update(objectId, newObject) {
        return KnexConnector.connection.from(this.tableName).where("id", objectId).update(newObject);
    }
    delete(objectId) {
        return KnexConnector.connection.from(this.tableName).where("id", objectId).delete()
    }
}
