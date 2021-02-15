import { TokenGenerator } from '../../common';

export default class JwtAuthHandler {
    constructor() {
        this.tokenGenerator = new TokenGenerator(process.env.JWT_SECRET, { audience: 'myaud', issuer: 'myissuer', subject: 'user', algorithm: process.env.JWT_ALGORITHM, expiresIn: process.env.JWT_EXPIRES })
    }

    check(request) {
        if (request.headers.authorization) {
            const token = (request.headers.authorization || '').split(' ')[1] || '';

            var decoded = this.tokenGenerator.verify(token);
            const { sub, username, exp } = decoded;

            if (!sub || !username || moment(exp).isAfter(new Date())) {
                return false;
            }
            return true;
        }
        return false;
    }

    validate(username, password) {


        return this.generateToken({ username });
    }

}