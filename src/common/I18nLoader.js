import fs from 'fs';
import path from 'path';
import util from 'util';

export default class I18nLoader {

    /**
     *
     * @param lang
     * @param callback
     */
    async load(custom) {
        const readfile = util.promisify(fs.readFile);
        const lang = custom || process.env.DEFAULT_LANG;

        let file = path.resolve(process.cwd(), "i18n/lang_" + lang + ".json")
        try {
            const data = await readfile(file, 'utf8');
            var parsedData = JSON.parse(data);

            this.currentData = parsedData;
        } catch (ex) {
            console.log("Lang file does not exist. Create it on ./i18n/lang_{xx}.json")
        }
    }

    /**
     * 
     * @param {*} key 
     */
    translate(key) {
        if (this.currentData && this.currentData[key]) {
            return this.currentData[key]
        }
        return "undefined." + key;
    }
}
