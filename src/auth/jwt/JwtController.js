
import express from 'express';
import moment from 'moment';
import url from 'url';
import { JsonResponse } from '..';
import { expressAsyncHandler } from 'express-async-handler'

import jsonwebtoken from 'jsonwebtoken'


export default class JwtController {

    constructor(publicPathsList, AuthHandler) {
        this.router = express.Router();
        this.publicPathsList = publicPathsList;

        this.AuthHandler = AuthHandler;

    }


    configure() {
        this.router.use(expressAsyncHandler((res, req, next) => { this.check(res, req, next); }));
        this.router.post('/login', expressAsyncHandler((res, req, next) => { this.loginPost(res, req, next); }));
        this.router.get('/refresh', expressAsyncHandler((res, req, next) => { this.refresh(res, req, next); }));

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

            if (request.headers.authorization) {
                const token = (request.headers.authorization || '').split(' ')[1] || '';

                var decoded = jsonwebtoken.verify(token, process.env.JWT_SECRET, { jwtid: 1, algorithm: process.env.JWT_ALGORITHM });
                const { sub, username, exp } = decoded;

                if (!sub || !username || moment(exp).isAfter(new Date())) {
                    return response.status(401).json(new JsonResponse(false, null, 'Unauthorized').toJson());
                }
                return next();
            }

            //Rutas ublicas 
            for (let path of this.publicPathsList) {
                const expr = pathToRegexp(path);
                if (expr.exec(url.parse(request.url).pathname) !== null) {
                    return next();
                }
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
                let token = this.AuthHandler.authorize(request.body.username, request.body.password)
                if (token) {
                    return response.status(200).json(new JsonResponse(true, { token: token }).toJson());
                }
                return response.status(401).json(new JsonResponse(false, null, 'Unauthorized').toJson());
            } catch (ex) {
                console.error(ex);
                return response.status(403).json(new JsonResponse(false, null, "Unauthorized").toJson());
            }
        }
        return response.status(403).json(new JsonResponse(false, null, "Unauthorized").toJson());
    }



    /**
     * Recarga un token
     * 
     * @param {*} request 
     * @param {*} response 
     * @param {*} ne-xt 
     */
    async refresh(request, response, next) {
        try {

            if (request.headers.authorization) {
                const token = (request.headers.authorization || '').split(' ')[1] || '';
                const tokenGenerator = new TokenGenerator(process.env.JWT_SECRET, { algorithm: process.env.JWT_ALGORITHM, keyid: '1', noTimestamp: false, expiresIn: '2m', notBefore: '2s' })


                var payload = jsonwebtoken.verify(token, process.env.JWT_SECRET, { algorithm: process.env.JWT_ALGORITHM });
                const newJtid = payload.jti + 1;
                delete payload.iat;
                delete payload.exp;
                delete payload.nbf;
                delete payload.jti; //We are generating a new token, if you are using jwtid during signing, pass it in refreshOptions
                const jwtSignOptions = Object.assign({}, this.options, { jwtid: refreshOptions.jwtid });


                return jwt.sign(payload, this.secretOrPrivateKey, { jwtid: newJti });


                if (!sub || !username || moment(exp).isAfter(new Date())) {
                    return response.status(401).json(new JsonResponse(false, null, 'Unauthorized').toJson());
                }
                return next();
            }

            return response.status(403).json(new JsonResponse(false, null, 'Unauthorized').toJson());
        } catch (ex) {
            console.error(ex);
            next("Error!");
        }
    }
}