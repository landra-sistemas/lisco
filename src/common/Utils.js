import crypto from 'crypto';
import util from 'util';

export default class Utils {
    static arrayToLower(mcArray) {
        let tmp = mcArray.join('~').toLowerCase();
        return tmp.split('~');
    }

    static replaceAll(str, find, replace) {
        return str.replace(new RegExp(find.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&'), 'g'), replace);
    }

    /**
     * Metodo de encript para las contraseñas y demas.
     * 
     * @param {*} text 
     */
    static encrypt(text) {
        const algorithm = 'aes-256-cbc';
        const secret = Buffer.from(process.env.CRYPT_SECRET, 'hex');
        const iv = Buffer.from(process.env.CRYPT_IV, 'hex');

        const cipher = crypto.createCipheriv(algorithm, secret, iv);
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return encrypted.toString('hex');
    }

    /**
     * Metodo de decrypt para las contraseñas y demas
     * @param {*} text 
     */
    static decrypt(text) {
        const algorithm = 'aes-256-cbc';
        const secret = Buffer.from(process.env.CRYPT_SECRET, 'hex');
        const iv = Buffer.from(process.env.CRYPT_IV, 'hex');

        const encryptedText = Buffer.from(text, 'hex');

        const decipher = crypto.createDecipheriv(algorithm, secret, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    }


    /**
     * 
     * Utiliza una promise para ejecutar un setTimeout y hacer un falso sleep.
     * 
     * @param {*} ms 
     */
    static sleep(ms) {
        let promise_sleep = util.promisify(setTimeout);

        return promise_sleep(ms);
    }

    /**
     * Genera dos claves para los metodos crypt y decrypt
     */
    static generateKeys() {
        return {
            key: crypto.randomBytes(32).toString('hex'),
            iv: crypto.randomBytes(16).toString('hex')
        }
    }


    /**
     * "aplana" un objeto jerarquico en una estructura clave-valor.
     * 
     * @param {*} ob 
     * @returns 
     */
    static flattenObject(ob) {
        let toReturn = {};
        let flatObject;
        for (let i in ob) {
            if (!ob.hasOwnProperty(i)) {
                continue;
            }
            //Devolver los arrays tal cual
            if (ob[i] && Array === ob[i].constructor) {
                toReturn[i] = ob[i];
                continue;
            }
            if ((typeof ob[i]) === 'object') {
                flatObject = Utils.flattenObject(ob[i]);
                for (let x in flatObject) {
                    if (!flatObject.hasOwnProperty(x)) {
                        continue;
                    }
                    //Exclude arrays from the final result
                    if (flatObject[x] && Array === flatObject.constructor) {
                        continue;
                    }
                    toReturn[i + (!!isNaN(x) ? '.' + x : '')] = flatObject[x];
                }
            } else {
                toReturn[i] = ob[i];
            }
        }
        return toReturn;
    }

    /**
     * Invierte un objeto aplanado recuperando su forma original
     * 
     * @param {*} data 
     * @returns 
     */
    static unflatten(data) {
        var result = {}
        for (var i in data) {
            var keys = i.split('.')
            keys.reduce(function (r, e, j) {
                return r[e] || (r[e] = isNaN(Number(keys[j + 1])) ? (keys.length - 1 == j ? data[i] : {}) : [])
            }, result)
        }
        return result
    }

    /**
     * 
     * @returns 
     */
    static expressHandler() {

        return (fn) => {
            return function asyncUtilWrap(...args) {
                const fnReturn = fn(...args);
                const next = args[args.length - 1];
                return Promise.resolve(fnReturn).catch((e) => {
                    return next(e);
                });
            };
        };
    }
}

