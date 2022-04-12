import { Utils } from "../../../common";

import { FQLParser, KnexParser } from "@landra_sistemas/fql-parser";
import { KnexConnector } from "..";

export default class KnexFilterParser {
    /**
     *
     * @param {*} builder
     * @param {*} string
     * @returns
     */
    static parseQueryString(builder, string, tableName) {
        const options = {
            allowGlobalSearch: true,
            caseInsensitive: true,
        };
        //Agregar los aliases en caso de que se hayan configurado de forma global
        if (KnexConnector.columnAliases && KnexConnector.columnAliases[tableName]) {
            options.aliases = KnexConnector.columnAliases[tableName];
        }
        const parser = new FQLParser(options);
        const data = parser.parse(string);

        return new KnexParser(tableName).toKnex(builder, data);
    }

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
    static parseFilters(builder, filter, tableName) {
        let query = builder;

        for (let prop in filter) {
            let elm = filter[prop];

            if (typeof elm === "object") {
                switch (elm.type) {
                    case "fql":
                        query = KnexFilterParser.parseQueryString(query, elm.value, tableName);
                        break;
                    case "date":
                    case "between":
                        if (elm.start && elm.end) {
                            query = query.whereBetween(prop, [elm.start, elm.end]);
                        }
                        if (elm.start && !elm.end) {
                            query = query.where(prop, ">=", elm.start);
                        }
                        if (!elm.start && elm.end) {
                            query = query.where(prop, ">=", elm.end);
                        }
                        break;
                    case "dateraw":
                    case "betweenraw":
                        if (elm.start && elm.end) {
                            query = query.whereRaw(`${prop} BETWEEN '?' AND '?'`, [elm.start, elm.end]);
                        }
                        if (elm.start && !elm.end) {
                            query = query.whereRaw(`${prop} >= '?'`, [elm.start]);
                        }
                        if (!elm.start && elm.end) {
                            query = query.whereRaw(`${prop} >= '?'`, [elm.start]);
                        }
                        break;
                    case "jsonb":
                        query = query.whereRaw(`${prop} ILIKE ?`, ["%" + elm.value + "%"]);
                        break;
                    case "full-text-psql":
                        query = query.whereRaw(`to_tsvector(${prop}::text) @@ to_tsquery(?)`, [elm.value]);
                        break;

                    case "greater":
                    case "greaterraw":
                        query = query.whereRaw(`${prop} > ?`, [elm.value]);
                        break;
                    case "greaterEq":
                    case "greaterEqraw":
                        query = query.whereRaw(`${prop} >= ?`, [elm.value]);
                        break;
                    case "less":
                    case "lessraw":
                        query = query.whereRaw(`${prop} < ?`, [elm.value]);
                        break;
                    case "lessEq":
                    case "lessEqraw":
                        query = query.whereRaw(`${prop} <= ?`, [elm.value]);
                        break;
                    case "exists":
                        query = query.whereExists(prop);
                        break;
                    case "notexists":
                        query = query.whereNotExists(prop);
                        break;
                    case "exact":
                    case "exactraw":
                        query = query.whereRaw(`${prop} = ?`, [elm.value]);
                        break;
                    case "in":
                        let propComplex = prop;
                        if (propComplex.includes(",")) {
                            propComplex = prop.split(",");
                        }
                        if (!Array.isArray(elm.value) && elm.value != undefined) {
                            query = query.whereIn(propComplex, elm.value.split(","));
                        } else {
                            if (elm.value != undefined) {
                                query = query.whereIn(propComplex, elm.value);
                            }
                        }
                        break;
                    case "inraw":
                        if (!Array.isArray(elm.value) && elm.value != undefined) {
                            query = query.whereRaw(`${prop} IN (?)`, [
                                elm.value
                                    .split(",")
                                    .map((e) => `'${e}'`)
                                    .join(","),
                            ]);
                        } else {
                            if (elm.value != undefined) {
                                query = query.whereRaw(`${prop} IN (?)`, [elm.value.map((e) => `'${e}'`).join(",")]);
                            }
                        }
                        break;
                    case "not":
                    case "notraw":
                        query = query.whereRaw(`${prop} != ?`, [elm.value]);
                        break;
                    case "like":
                    case "likeraw":
                        let value_likeraw = Utils.replaceAll(elm.value, "*", "%");
                        query = query.whereRaw(` ${prop} LIKE ?`, [value_likeraw]);
                        break;
                    case "notlike":
                    case "notlikeraw":
                        let value_nolikeraw = Utils.replaceAll(elm.value, "*", "%");
                        query = query.whereRaw(` ${prop} NOT LIKE ?`, [value_nolikeraw]);
                        break;
                    case "likeI":
                        let value_rawilike = Utils.replaceAll(elm.value, "*", "%");
                        query = query.whereRaw(` ${prop} ILIKE ?`, [value_rawilike]);
                        break;
                    case "notlikeI":
                        let value_notrawilike = Utils.replaceAll(elm.value, "*", "%");
                        query = query.whereRaw(` ${prop} NOT ILIKE ?`, [value_notrawilike]);
                        break;
                    case "null":
                    case "nullraw":
                        query = query.whereRaw(`${prop} is NULL`);
                        break;
                    case "notnull":
                    case "notnullraw":
                        query = query.whereRaw(`${prop} is not NULL`);
                        break;
                }
            } else {
                //Si el valor no es un objeto se devuelve
                query = query.where(prop, elm);
            }
        }

        // console.log(query.toSQL());
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
        if (sort.direction === "descend") {
            direction = "DESC";
        }

        return sort.field + " " + direction;
    }
}
