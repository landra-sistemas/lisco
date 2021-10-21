import fs from 'fs';
import path from 'path';
import util from 'util';
import Utils from './Utils';

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
        if (!this.currentDataFlat) {
            this.currentDataFlat = {};
        }
        //TODO mejorar el sistema cargando todas las traducciones del directorio i18n con chokidar esperando modificaciones

        let file = path.resolve(process.cwd(), "i18n/lang_" + lang + ".json")
        try {
            const data = await readfile(file, 'utf8');
            var parsedData = JSON.parse(data);

            this.currentDataFlat[lang] = Utils.flattenObject(parsedData);
            this.currentData[lang] = parsedData;
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

        if (this.currentDataFlat && this.currentDataFlat[lang] && this.currentDataFlat[lang][key]) {
            return this.currentData[lang][key]
        }

        if (!this.currentDataFlat || !this.currentDataFlat[lang]) {
            await this.load(lang);
            if (this.currentDataFlat && this.currentDataFlat[lang] && this.currentDataFlat[key]) {
                return this.currentDataFlat[lang][key]
            }
        }
        return "undefined." + key;
    }
}

