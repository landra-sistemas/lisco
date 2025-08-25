import express from "express";
import url from "url";
import { JsonResponse, Utils } from "../common/index.js";

import { pathToRegexp } from "path-to-regexp";

export default class AuthController {
    constructor(publicPathsList, AuthHandler) {
        this.router = express.Router();
        this.publicPathsList = [...publicPathsList, "/login"];

        this.AuthHandler = AuthHandler;
    }

    configure() {
        const exAsync = Utils.expressHandler();
        this.router.use(exAsync((...args) => this.check(...args)));
        this.router.post(
            "/login",
            exAsync((...args) => this.loginPost(...args))
        );
        this.router.post(
            "/logout",
            exAsync((...args) => this.logout(...args))
        );

        return this.router;
    }

    /**
     * Controla que los usuarios tengan sesion para acceder a los metodos privados de la API
     *
     * @param {*} request
     * @param {*} response
     * @param {*} next
     */
    async check(request, response, next) {
        try {
            //Rutas ublicas
            for (let path of this.publicPathsList) {
                const expr = pathToRegexp(path);
                if (expr.exec(request.originalUrl) !== null) {
                    return next();
                }
            }

            if (await this.AuthHandler.check(request)) {
                return next();
            }

            return response.status(403).json(new JsonResponse(false, null, "Forbidden").toJson());
        } catch (ex) {
            console.error(ex);
            return response.status(403).json(new JsonResponse(false, null, "Forbidden").toJson());
        }
    }

    /**
     * Valida los credenciales de un usuario
     *
     * TODO logger console.custom("access", INFO);
     *
     * @param {*} request
     * @param {*} response
     */
    async loginPost(request, response) {
        if (request.body.username) {
            try {
                let data = await this.AuthHandler.validate(request, request.body.username, request.body.password);
                if (data) {
                    return response.status(200).json(new JsonResponse(true, data).toJson());
                }
                return response.status(401).json(new JsonResponse(false, null, "Unauthorized - Incorrect credentials").toJson());
            } catch (ex) {
                console.error(ex);
                return response.status(401).json(new JsonResponse(false, null, "Unauthorized - Error, check log").toJson());
            }
        }
        return response.status(401).json(new JsonResponse(false, null, "Unauthorized - Missing parameters").toJson());
    }

    /**
     * Cierra la sesion del usuario
     *
     * @param {*} request
     * @param {*} response
     */
    async logout(request, response) {
        if (this.AuthHandler.logout) {
            //Depende de que el authHandler implementado pueda realizar esta accion
            try {
                await this.AuthHandler.logout(request);
                return response.status(200).json(new JsonResponse(true).toJson());
            } catch (ex) {
                console.error(ex);
                return response.status(500).json(new JsonResponse(false, null, ex).toJson());
            }
        }
        return response.status(200).json(new JsonResponse(true).toJson());
    }
}
