import express from "express";
import { JsonResponse, Utils } from "../common/index.js";

export class BaseController {
    constructor() {
        this.router = express.Router();
        this.routes = {};
        //Example routes shorthand
        /*
         {
            "/": {
                "get": this.listEntidad.bind(this),
                "post": this.listEntidad.bind(this)
            }
         } 
         */
    }

    configure(entity, config) {
        if (!entity) {
            return this.router;
        }

        const exAsync = Utils.expressHandler();
        this.router.get(
            `/${entity}`,
            exAsync((...args) => this.listEntidad(...args))
        );
        this.router.post(
            `/${entity}/list`,
            exAsync((...args) => this.listEntidad(...args))
        );
        this.router.get(
            `/${entity}/:id`,
            exAsync((...args) => this.getEntidad(...args))
        );
        this.router.post(
            `/${entity}`,
            exAsync((...args) => this.saveEntidad(...args))
        );
        this.router.put(
            `/${entity}/:id`,
            exAsync((...args) => this.updateEntidad(...args))
        );
        this.router.delete(
            `/${entity}/:id`,
            exAsync((...args) => this.deleteEntidad(...args))
        );

        this.service = config.service;
        this.table = config.table;
        this.schema = config.schema;

        return this.router;
    }

    /**
     * Lista entidades en la aplicacion, es posible enviarle parametros de filtrado.
     *
     *
     * @api {post} /:entidad/list Listar entidades
     * @apiName Listar entidades
     * @apiGroup Comun
     * @apiPermission Auth Basic username:pwd
     * @apiParam {Number} id entidades unique ID.
     *
     * @apiSuccess {Boolean} success
     * @apiSuccess {Object[]} data  dataObject
     */
    async listEntidad(request, response, next) {
        try {
            let service = new this.service(null, this.table);
            let filters = request.method === "POST" ? request.body : request.query && request.query.filters ? JSON.parse(request.query.filters) : {};

            let data = await service.list(filters, filters.start, filters.limit);
            let jsRes = new JsonResponse(true, data.data, null, data.total);

            response.json(jsRes.toJson());
        } catch (e) {
            next(e);
        }
    }
    /**
     *Obtiene un elemento concreto mediante su identificador
     *
     *
     * @api {get} /:entidad/:id Obtener entidad
     * @apiName Obtener entidad
     * @apiGroup Comun
     * @apiPermission Auth Basic username:pwd
     * @apiParam {Number} id entidades unique ID.
     *
     * @apiSuccess {Boolean} success
     * @apiSuccess {Object[]} data  dataObject
     */
    async getEntidad(request, response, next) {
        try {
            let service = new this.service(null, this.table);
            let data = await service.loadById(request.params.id);
            let jsRes = new JsonResponse(true, data);
            let code = 200;
            if (data == null) {
                code = 404;
                let message = "Element not found";
                jsRes = new JsonResponse(false, null, message, 0);
            }

            response.status(code).json(jsRes.toJson());
        } catch (e) {
            console.error(e);
            let message = "";
            if (e.code == "22P02") {
                //PostgreSQL error Code form string_to_UUID
                message = "Expected uiid";
            }
            let jsRes = new JsonResponse(false, null, message, 0);
            response.status(400).json(jsRes.toJson());
        }
    }

    /**
     * Almacena un elemento en BD
     *
     *
     * @api {post} /:entidad/:id Crear entidad
     * @apiName Crear entidad
     * @apiGroup Comun
     * @apiPermission Auth Basic username:pwd
     * @apiParam {Number} id entidades unique ID.
     *
     * @apiSuccess {Boolean} success
     * @apiSuccess {Object[]} data  dataObject
     */
    async saveEntidad(request, response, next) {
        try {
            let service = new this.service(null, this.table);
            let requestBody = request?.body;
            if (this.schema) {
                requestBody = await this.schema?.validate(request?.body);
            }

            let data = await service.save(requestBody);
            let jsRes = new JsonResponse(true, (data && data[0]) || { id: request.body.id });

            response.setHeader("Location", `/entity/${jsRes.data.id}`);
            response.status(201).json(jsRes.toJson());
        } catch (e) {
            next(e);
        }
    }

    /**
     * Almacena un elemento en BD
     *
     *
     * @api {put} /:entidad/:id Actualizar entidad
     * @apiName Actualizar entidad
     * @apiGroup Comun
     * @apiPermission Auth Basic username:pwd
     * @apiParam {Number} id entidades unique ID.
     *
     * @apiSuccess {Boolean} success
     * @apiSuccess {Object[]} data  dataObject
     */
    async updateEntidad(request, response, next) {
        try {
            let service = new this.service(null, this.table);
            let requestBody = request?.body;
            if (this.schema) {
                requestBody = await this.schema?.validate(request?.body);
            }

            let data = await service.update(request.params.id, requestBody);
            let jsRes = new JsonResponse(true, (data && data[0]) || { id: request.body.id });

            response.json(jsRes.toJson());
        } catch (e) {
            next(e);
        }
    }

    /**
     * Elimina un elemento correspondiente al identificador recibido
     *
     *
     * @api {delete} /:entidad/:id/delete Delete entidad
     * @apiName Eliminar entidad
     * @apiGroup Comun
     * @apiPermission Auth Basic username:pwd
     * @apiParam {Number} id entidades unique ID.
     *
     * @apiSuccess {Boolean} success
     * @apiSuccess {Object[]} data  dataObject
     */
    async deleteEntidad(request, response, next) {
        try {
            let service = new this.service(null, this.table);
            let data = await service.delete(request.params.id);
            let jsRes = new JsonResponse(true, data);

            response.status(204).json(jsRes.toJson());
        } catch (e) {
            console.error(e);
            if (e == "NotFound") {
                let message = "Element not found";
                let jsRes = new JsonResponse(false, null, message, 0);
                response.status(404).json(jsRes.toJson());
            } else {
                next(e);
            }
        }
    }
}
