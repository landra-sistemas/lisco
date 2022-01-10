import { BaseKnexDao } from '../db';

export class BaseService {


    constructor(cls) {
        if (cls) {
            this.dao = new cls();
        } else {
            this.dao = new BaseKnexDao(); //El sistema por defecto utiliza knex, si se pasa un dao personalizado se puede sobreescribir este comportamiento
        }
    }
    /**
     * Obtencion de una lista de elementos.
     *
     * filters, es opcional. Si no se pasan se devuelve lo que hay ;
     */
    async list(filters, start, limit) {
        //Pagination
        var start = start || 0;
        var limit = limit || 1000;//Default limit

        let response = {};
        response.total = await this.dao.countFilteredData(filters, start, limit);

        if (filters && Object.keys(filters).length !== 0) {
            let filteredData = await this.dao.loadFilteredData(filters, start, limit)
            response.data = filteredData
            return response;
        }

        response.data = await this.dao.loadAllData(start, limit);
        return response;
    }

    async listWithRelations(filters, start, limit, relation_config) {
        //Pagination
        var start = start || 0;
        var limit = limit || 1000;//Default limit

        if (!filters) {
            filters = {};
        }

        let response = {};
        response.total = await this.dao.countFilteredData(filters, start, limit);

        let filteredData = await this.dao.loadFilteredDataWithRelations(filters, start, limit, relation_config);
        response.data = filteredData;
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

