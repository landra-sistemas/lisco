import { v4 as uuidv4 } from 'uuid';
import KnexFilterParser from '../filters/KnexFilterParser';
import KnexConnector from '../KnexConnector';

/**
 * Crear un dao con los métodos básicos
 */
export default class BaseKnexDao {

    constructor(tableName) {
        this.tableName = tableName;
    }


    loadAllData(start, limit) {
        return KnexConnector.connection.select('*').from(this.tableName).limit(limit).offset(start)
    }

    async loadFilteredData(filters, start, limit) {
        let parser = new KnexFilterParser();
        let sorts = [];
        if (filters.sort) {
            sorts = parser.parseSort(filters.sort);
        }

        return KnexConnector.connection.from(this.tableName).where((builder) => (
            parser.parseFilters(builder, lodash.omit(filters, ['sort']))
        )).orderBy(sorts).limit(limit).offset(start);

    }

    async countFilteredData(filters) {
        let parser = new KnexFilterParser();
        return KnexConnector.connection.from(this.tableName).where((builder) => (
            parser.parseFilters(builder, lodash.omit(filters, ['sort']))
        ));
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
    remove(objectId) {
        return KnexConnector.connection.from(this.tableName).where("id", objectId).delete()
    }
}
