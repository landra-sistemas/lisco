import fs from 'fs';
import path from 'path';
import util from 'util';
import { Utils } from '.';

export default class I18nLoader {
    
    /**
     *
     * @param lang
     * @param callback
     */
    async load(custom) {
        const readfile = util.promisify(fs.readFile);
        const lang = custom || process.env.DEFAULT_LANG;

        if (!this.currentData) {
            this.currentData = {};
        }
        //TODO mejorar el sistema cargando todas las traducciones del directorio i18n con chokidar esperando modificaciones

        let file = path.resolve(process.cwd(), "i18n/lang_" + lang + ".json")
        try {
            const data = await readfile(file, 'utf8');
            var parsedData = JSON.parse(data);

            this.currentData[lang] = Utils.flattenObject(parsedData);
        } catch (ex) {
            console.log("Lang file does not exist. Create it on ./i18n/lang_{xx}.json")
        }
    }

    /**
     * 
     * @param {*} key 
     */
    async translate(key, lang) {
        if (!lang) lang = process.env.DEFAULT_LANG

        if (this.currentData && this.currentData[lang] && this.currentData[lang][key]) {
            return this.currentData[lang][key]
        }

        if (!this.currentData || !this.currentData[lang]) {
            await this.load(lang);
            if (this.currentData && this.currentData[lang] && this.currentData[key]) {
                return this.currentData[lang][key]
            }
        }
        return "undefined." + key;
    }
}

