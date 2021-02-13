
import jsonwebtoken from 'jsonwebtoken'

export default class JwtAuthHandler {
    constructor() {

    }

    validate(username, password) {


        return this.generateToken({ username });
    }

    /**
     * 
     * @param {*} user 
     */
    generateToken(user) {
        const payload = {
            sub: user.id,
            exp: Date.now() + parseInt(process.env.JWT_LIFETIME),
            username: user.username
        };
        const token = jsonwebtoken.sign(JSON.stringify(payload), process.env.JWT_SECRET, { algorithm: process.env.JWT_ALGORITHM });
        return token;
    }
}