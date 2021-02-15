/**
 * Example to refresh tokens using https://github.com/auth0/node-jsonwebtoken
 * It was requested to be introduced at as part of the jsonwebtoken library,
 * since we feel it does not add too much value but it will add code to mantain
 * we won't include it.
 *
 * I create this gist just to help those who want to auto-refresh JWTs.
 */
import jsonwebtoken from 'jsonwebtoken';
import * as uuid from 'uuid';

export default class TokenGenerator {

    constructor(privateKey, options) {
        this.privateKey = privateKey;
        this.options = options;
    }

    sign(payload) {
        const jwtSignOptions = { ...this.options, jwtid: uuid.v4() };
        return jsonwebtoken.sign(payload, this.privateKey, jwtSignOptions);
    }

    verify(token) {
        return jsonwebtoken.verify(token, this.privateKey, this.options);
    }

    refresh(token) {
        const payload = jsonwebtoken.verify(token, this.privateKey, this.options);
        delete payload.sub;
        delete payload.iss;
        delete payload.aud;
        delete payload.iat;
        delete payload.exp;
        delete payload.nbf;
        delete payload.jti; //We are generating a new token, if you are using jwtid during signing, pass it in refreshOptions
        const jwtSignOptions = { ...this.options, jwtid: uuid.v4() };
        // The first signing converted all needed options into claims, they are already in the payload
        return jsonwebtoken.sign(payload, this.privateKey, jwtSignOptions);
    }
}
