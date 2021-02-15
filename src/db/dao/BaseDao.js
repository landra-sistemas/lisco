import { v4 as uuidv4 } from 'uuid';
import { promisify } from 'util';
import FilterParser from '../filters/FilterParser';
import { filter } from 'compression';
/**
 * Crear un dao con esta estructura pero contra MongoDB
 * 
 */
export default class BaseDao {

    constructor(tableName) {
        this.tableName = tableName;
    }


    loadAllData(start, limit) {
        return global.knex.select('*').from(this.tableName).limit(limit).offset(start)
    }

    async loadFilteredData(filters, start, limit) {
        let parser = new FilterParser();
        let sorts = [];
        if (filters.sort) {
            sorts = parser.parseSort(filters.sort);
        }

        return global.knex.from(this.tableName).where((builder) => (
            parser.parseFilters(builder, lodash.omit(filters, ['sort']))
        )).orderBy(sorts).limit(limit).offset(start);

    }

    async countFilteredData(filters) {
        let parser = new FilterParser();
        return global.knex.from(this.tableName).where((builder) => (
            parser.parseFilters(builder, lodash.omit(filters, ['sort']))
        ));
    }

    async loadById(objectId) {
        return global.knex.from(this.tableName).where('id', objectId);
    }
    
    save(object) {
        if (!object.id) {
            object.id = uuidv4();
        }

        const qry = global.querys.getQuery(this.tableName, "insert");

        return this.promisifyQuery().execute(qry, [object]);
    }
    update(objectId, newObject) {
        const qry = global.querys.getQuery(this.tableName, "update");

        return this.promisifyQuery().execute(qry, [newObject, objectId]);
    }
    remove(objectId) {
        const qry = global.querys.getQuery(this.tableName, "delete");

        return this.promisifyQuery().execute(qry, [objectId]);
    }
}
