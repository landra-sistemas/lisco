import { BaseKnexDao } from "../db";

export class BaseService {
    constructor(cls, table) {
        if (cls) {
            this.dao = new cls();
        } else {
            this.dao = new BaseKnexDao(); //El sistema por defecto utiliza knex, si se pasa un dao personalizado se puede sobreescribir este comportamiento
        }
        if (table) {
            this.dao.tableName = table;
        }
    }
    /**
     * Obtencion de una lista de elementos.
     *
     * filters, es opcional. Si no se pasan se devuelve lo que hay ;
     */
    async list(filters, start, limit) {
        //Pagination
        const st = start || 0;
        const lm = limit || 1000; //Default limit

        let response = {};
        response.total = await this.dao.countFilteredData(filters, st, lm);

        if (filters && Object.keys(filters).length !== 0) {
            let filteredData = await this.dao.loadFilteredData(filters, st, lm);
            response.data = filteredData;
            return response;
        }

        response.data = await this.dao.loadAllData(start, limit);
        return response;
    }

    /**
     * Obtencion de un elemento mediante su identificador
     */
    loadById(id) {
        return this.dao.loadById(id);
    }
    /**
     * Metodo de creacion.
     *
     * Si el identificador se pasa como undefined se creara un nuevo elemento,
     * sino se modifica el correspondiente.
     */
    save(data) {
        //Create
        return this.dao.save(data);
    }
    /**
     * Metodo de creacion.
     *
     * Si el identificador se pasa como undefined se creara un nuevo elemento,
     * sino se modifica el correspondiente.
     */
    update(id, data) {
        if (id) {
            //Update
            return this.dao.update(id, data);
        }
    }
    /**
     * Metodo de eliminado.
     *
     * El identificador es obligatorio para poder localizar el elemento a eliminar.
     */
    delete(id) {
        if (id) {
            return this.dao.delete(id);
        }
    }
}
