import { Utils } from "../../../common";

export default class KnexFilterParser {


    /**
     * Convierte un objeto clave valor en un conjunto de filtros.
     *
     * - Filtro estandar:
     *    filters: {
     *       "column": "value" -> filtro generico exact
     *    }
     * - Filtro Objeto:
     *    filters:{
     *       "column": {
     *       "type": "date|between|exists|notexists|greater|greaterEq|less|lessEq|exact|exactI|not|null|notnull|like|likeI"
     *       "start": "xxx", //inicio de rango para el filtro de date y between
     *       "end": "xxx", //fin de rango para el filtro date y between
     *       "value": "xxx" //valor a utilizar para el resto de filtros
     *     }
     * }
     *  - Filtro Lista:
     *     filters: {
     *       "column": [1, 2, 3]
     *     }
     *    Filtro de tipo IN, todos los elementos que coincidan
     * 
     * - Definicion de tipos:
     *    date: filtro de fechas desde y hasta
     *    between: filtro entre dos valores concretos
     *    exists: busca si existe la propiedad
     *    notexists: busca si existe la propiedad
     *    greater: mayor que
     *    greaterEq: mayor o igual que
     *    less: menor que
     *    lessEq: menor o igual que
     *    exact: valor exacto
     *    exactI: valor exacto ignorando mayusculas y minusculas
     *    not: distinto de
     *    null: igual a null
     *    notnull: distinto de null
     *    like: filtro like
     *    likeI: filtro like ignorando mayusculas y minusculas
     */
    static parseFilters(builder, filter) {
        let query = builder;

        for (let prop in filter) {

            let elm = filter[prop];

            if (typeof elm === 'object') {

                switch (elm.type) {
                    case 'date':
                    case 'between':
                        if (elm.start && elm.end) {
                            query = query.whereBetween(prop, [elm.start, elm.end]);
                        }
                        if (elm.start && !elm.end) {
                            query = query.where(prop, '>=', elm.start);
                        }
                        if (!elm.start && elm.end) {
                            query = query.where(prop, '>=', elm.end);
                        }
                        break;
                    case 'jsonb':
                        query = query.whereRaw(prop + " ILIKE ?", ["%" + elm.value + "%"]);
                        break;
                    case 'full-text-psql':
                        query = query.whereRaw(`to_tsvector(${prop}::text) @@ to_tsquery('${elm.value}')`);
                        break;
                    case 'greater':
                        query = query.where(prop, '>', elm.value);
                        break;
                    case 'greaterEq':
                        query = query.where(prop, '>=', elm.value);
                        break;
                    case 'less':
                        query = query.where(prop, '<', elm.value);
                        break;
                    case 'lessEq':
                        query = query.where(prop, '<=', elm.value);
                        break;
                    case 'exists':
                        query = query.whereExists(prop);
                        break;
                    case 'notexists':
                        query = query.whereNotExists(prop);
                        break;
                    case 'exact':
                        query = query.where(prop, elm.value);
                        break;
                    case 'exactI':
                        //!FIXME https://github.com/knex/knex/issues/233
                        query = query.where(prop, 'ILIKE', elm.value);
                        break;
                    case 'in':
                        let propComplex = prop;
                        if (propComplex.includes(",")) {
                            propComplex = prop.split(',');
                        }
                        if (!Array.isArray(elm.value) && elm.value != undefined) {
                            query = query.whereIn(propComplex, elm.value.split(','));
                        } else {
                            if(elm.value != undefined){
                                query = query.whereIn(propComplex, elm.value);
                            }
                        }
                        break;
                    case 'not':
                        query = query.whereNot(prop, elm.value);
                        break;
                    case 'like':
                        let value_like = Utils.replaceAll(elm.value, '*', '%');
                        query = query.where(prop, 'LIKE', value_like);
                        break;
                    case 'likeI':
                        //!FIXME https://github.com/knex/knex/issues/233
                        let value_ilike = Utils.replaceAll(elm.value, '*', '%');
                        query = query.where(prop, 'ILIKE', value_ilike);
                        break;
                    case 'null':
                        query = query.whereNull(prop);
                        break;
                    case 'notnull':
                        query = query.whereNotNull(prop);
                        break;
                }
            } else {
                //Si el valor no es un objeto se devuelve
                query = query.where(prop, elm);
            }
        }
        return query;
    }

    /**
     * Conversion de un objeto {property: XX, direction: ASC|DESC - ascend|descend} a un ORDER BY
     * 
     * @param {*} sorts 
     */
    static parseSort(sort) {
        if (!sort.field || !sort.direction) {
            return 1;
        }

        let direction = "ASC";
        if (sort.direction === 'descend') {
            direction = "DESC";
        }


        return sort.field + " " + direction;
    }

}