import { TokenGenerator, Utils } from '../../common';
import IAuthHandler from '../IAuthHandler'
import lodash from 'lodash';

export default class JwtAuthHandler extends IAuthHandler {
    constructor(UserDao) {
        this.tokenGenerator = new TokenGenerator(process.env.JWT_SECRET, { audience: process.env.JWT_AUDIENCE, issuer: process.env.JWT_ISSUER, subject: process.env.JWT_SUBJECT, algorithm: process.env.JWT_ALGORITHM, expiresIn: process.env.JWT_EXPIRES })

        if(!UserDao){
            throw new Error("Need 'UserDao' for user validation. Create 'UserDao' class extending 'IUserDao'");
        }
        this.userDao = new UserDao();
    }

    /**
     * Metodo encargado de realizar la comprobacion para validar si la sesion del usuario es válida
     * 
     * @param {*} request 
     */
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

    /**
     * Método encargado de realizar la validación de un usuario. Utiliza IUserDao como interfaz para la realización de la query a BD.
     * 
     * @param {*} username 
     * @param {*} password 
     */
    async validate(username, password) {

        const user = await this.userDao.findByUsername(username);

        //TODO quizas poder configurar los nombres de username y password

        if (user.username === username && user.password === Utils.encrypt(password)) {
            return this.generateToken(lodash.omit(user, ['password']));
        }

    }


}