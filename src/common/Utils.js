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

    static encrypt(text) {
        const algorithm = 'aes-256-cbc';
        const secret = Buffer.from(process.env.CRYPT_SECRET, 'hex');
        const iv = Buffer.from(process.env.CRYPT_IV, 'hex');

        const cipher = crypto.createCipheriv(algorithm, secret, iv);
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return encrypted.toString('hex');
    }

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
     * @param {*} ms 
     */
    static sleep(ms) {
        let promise_sleep = util.promisify(setTimeout);

        return promise_sleep(ms);
    }

    /**
     * 
     */
    static generateKeys() {
        return {
            key: crypto.randomBytes(32).toString('hex'),
            iv: crypto.randomBytes(16).toString('hex')
        }
    }

}

