
import express from 'express';
import url from 'url';
import { JsonResponse } from '../common';
import expressAsyncHandler from 'express-async-handler'



export default class AuthController {

    constructor(publicPathsList, AuthHandler) {
        this.router = express.Router();
        this.publicPathsList = publicPathsList;

        this.AuthHandler = AuthHandler;

    }


    configure() {
        this.router.use(expressAsyncHandler((res, req, next) => { this.check(res, req, next); }));
        this.router.post('/login', expressAsyncHandler((res, req, next) => { this.loginPost(res, req, next); }));

        return this.router;
    }

    /**
     * Controla que los usuarios tengan sesion para acceder a los metodos privados de la API
     * 
     * @param {*} request 
     * @param {*} response 
     * @param {*} ne-xt 
     */
    async check(request, response, next) {
        try {
            //Rutas ublicas 
            for (let path of this.publicPathsList) {
                const expr = pathToRegexp(path);
                if (expr.exec(url.parse(request.url).pathname) !== null) {
                    return next();
                }
            }

            if (!this.AuthHandler.check(request)) {
                return response.status(403).json(new JsonResponse(false, null, 'Unauthorized').toJson());
            }

            return response.status(403).json(new JsonResponse(false, null, 'Unauthorized').toJson());
        } catch (ex) {
            console.error(ex);
            next("Error!");
        }
    }


    /**
     * Valida los credenciales de un usuario
     * 
     * @param {*} request 
     * @param {*} response 
     */
    async loginPost(request, response) {
        if (request.body.username) {
            try {
                let data = this.AuthHandler.authorize(request.body.username, request.body.password)
                if (data) {
                    return response.status(200).json(new JsonResponse(true, data).toJson());
                }
                return response.status(401).json(new JsonResponse(false, null, 'Unauthorized').toJson());
            } catch (ex) {
                console.error(ex);
                return response.status(403).json(new JsonResponse(false, null, "Unauthorized").toJson());
            }
        }
        return response.status(403).json(new JsonResponse(false, null, "Unauthorized").toJson());
    }



}