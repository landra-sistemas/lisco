import fs from 'fs';
import path from 'path';
import util from 'util';
import Utils from './Utils';


import chokidar from 'chokidar';

export default class I18nLoader {


    constructor() {
        this.watcher = {};
    }


    /**
     *
     * @param lang
     * @param callback
     */
    async load(custom) {
        const lang = custom || process.env.DEFAULT_LANG;

        if (!this.currentData) {
            this.currentData = {};
        }
        if (!this.currentDataFlat) {
            this.currentDataFlat = {};
        }

        const file = process.cwd() + "/i18n/lang_" + lang + ".json";

        // Initialize watcher.
        this.watcher[lang] = chokidar.watch(file, {
            ignored: /(^|[\/\\])\../, // ignore dotfiles
            persistent: true
        });
        //Add change watcher
        this.watcher[lang]
            .on('change', path => this.loadFile(path, lang));

        //Initialize file load
        await this.loadFile(file, lang)
    }

    /**
     * Carga el archivo de traducciones.
     * 
     * @param {*} file 
     * @param {*} lang 
     */
    async loadFile(file, lang) {
        const readfile = util.promisify(fs.readFile);
        try {
            const data = await readfile(file, 'utf8');
            var parsedData = JSON.parse(data);

            this.currentDataFlat[lang] = Utils.flattenObject(parsedData);
            this.currentData[lang] = parsedData;
        } catch (ex) {
            console.error(ex)
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

