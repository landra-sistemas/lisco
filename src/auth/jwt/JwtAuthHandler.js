import { TokenGenerator, Utils } from '../../common/index.js';
import IAuthHandler from '../IAuthHandler.js'
import lodash from 'lodash';
import moment from 'moment';

export default class JwtAuthHandler extends IAuthHandler {
    constructor(UserDao) {
        super();

        this.tokenGenerator = new TokenGenerator(process.env.JWT_SECRET, { audience: process.env.JWT_AUDIENCE, issuer: process.env.JWT_ISSUER, subject: process.env.JWT_SUBJECT, algorithm: process.env.JWT_ALGORITHM, expiresIn: process.env.JWT_EXPIRES })

        if (!UserDao) {
            throw new Error("Need 'UserDao' for user validation. Create 'UserDao' class extending 'IUserDao'");
        }
        this.userDao = UserDao;
    }

    /**
     * Metodo encargado de realizar la comprobacion para validar si la sesion del usuario es válida
     * 
     * @param {*} request 
     */
    async check(request) {
        if (request.headers.authorization) {
            const token = (request.headers.authorization || '').split(' ')[1] || '';

            if (!token) {
                console.error("Token needed");
                return false;
            }
            try {
                var decoded = this.tokenGenerator.verify(token);
                const { sub, username, exp } = decoded;

                if (!sub || !username || moment(exp).isAfter(new Date())) {
                    return false;
                }

                //Si la sesion es valida, lo introducimos en el contexto de la solicitud
                request.session = { ...request.session, ...decoded };
                return true;
            } catch (ex) {
                console.error(ex);
                return false;
            }
        }
        return false;
    }

    /**
     * Método encargado de realizar la validación de un usuario. Utiliza IUserDao como interfaz para la realización de la query a BD.
     * 
     * @param {*} username 
     * @param {*} password 
     */
    async validate(request, username, password) {

        const user = await this.userDao.findByUsername(username);

        if (user && user.username === username && user.password === Utils.encrypt(password)) {
            return this.tokenGenerator.sign(lodash.omit(user, ['password']));
        }

        return false;
    }

}