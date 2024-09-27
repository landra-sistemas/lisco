import { Utils } from "../../common/index.js";
import IAuthHandler from "../IAuthHandler.js";
import lodash from "lodash";

/**
 * Necesario:
 *  Instalar -->   express-session y algun session store
 * 
 *  Mas info: https://www.npmjs.com/package/express-session
 * 
 *  App.customizeExpress = () => {
       this.app.use(session({
            secret: 'keyboard cat',
            resave: false,
            saveUninitialized: true,
            cookie: { secure: true }
        }));
    }
 */

export default class CookieAuthHandler extends IAuthHandler {
    constructor(UserDao) {
        super();

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
            //Si se recibe por Auth Basic
            const token = (request.headers.authorization || "").split(" ")[1] || "";

            const creds = Buffer.from(token, "base64").toString().split(":");
            const login = creds[0];
            const password = creds[1];

            if (!(await this.validate(request, login, password))) {
                return false;
            }
            return true;
        }
        if (request.session && request.session.username) {
            //Si hay sesion almacenada
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
    async validate(request, username, password) {
        const user = await this.userDao.findByUsername(username);

        if (user && user.username === username && user.password === Utils.encrypt(password)) {
            const userInfo = lodash.omit(user, ["password"]);
            for (let key in userInfo) {
                request.session[key] = userInfo[key];
            }

            return true;
        }
        return false;
    }

    /**
     *
     * @param {*} request
     */
    logout(request) {
        return new Promise((resolve) => {
            if (request.session) {
                request.session.destroy(resolve);
            }
        });
    }
}
