import express from 'express';
import { JsonResponse } from '../common';

const asyncHandler = require('express-async-handler')


export class BaseController {


    constructor() {
        this.router = express.Router();
    }

    configure(entity, config) {
        this.router.post(`/${entity}/list`, asyncHandler((res, req, next) => { this.listEntidad(res, req, next); }));
        this.router.get(`/${entity}/:id`, asyncHandler((res, req, next) => { this.getEntidad(res, req, next); }));
        this.router.post(`/${entity}`, asyncHandler((res, req, next) => { this.saveEntidad(res, req, next); }));
        this.router.put(`/${entity}/:id`, asyncHandler((res, req, next) => { this.updateEntidad(res, req, next); }));
        this.router.delete(`/${entity}/:id`, asyncHandler((res, req, next) => { this.deleteEntidad(res, req, next); }));

        this.service = config.service;

        return this.router;
    }

    /**
     * Lista entidades en la aplicacion, es posible enviarle parametros de filtrado.
     *
     * !FIXME Todavia no se ha definido la lista de parametros a utilizar para el filtrado.
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
            let service = new this.service();
            let filters = request.body;

            let data = await service.list(filters, filters.start, filters.limit);
            let jsRes = new JsonResponse(true, data, null, data.total);

            response.json(jsRes.toJson());
        } catch (e) {
            next(e)
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
            let service = new this.service();
            let data = await service.loadById(request.params.id);
            let jsRes = new JsonResponse(true, data);

            response.json(jsRes.toJson());

        } catch (e) {
            next(e)
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
            let service = new this.service();

            let data = await service.save(request.body);
            let jsRes = new JsonResponse(true, { id: request.body.id || data[0] });

            response.json(jsRes.toJson());

        } catch (e) {
            next(e)
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
            let service = new this.service();

            let data = await service.update(request.params.id, request.body);
            let jsRes = new JsonResponse(true, { id: request.body.id || data[0] });

            response.json(jsRes.toJson());

        } catch (e) {
            next(e)
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
            let service = new this.service();
            let data = await service.delete(request.params.id);
            let jsRes = new JsonResponse(true, data);

            response.json(jsRes.toJson());

        } catch (e) {
            next(e)
        }
    }

}

