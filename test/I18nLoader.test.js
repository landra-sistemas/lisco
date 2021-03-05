import { expect } from 'chai';
import { I18nLoader } from '../src';


describe('I18nLoader', () => {

    it('#load()', async () => {

        let i18n = I18nLoader;
        await i18n.load();

        expect(i18n).not.to.be.undefined;
        expect(i18n.currentData).not.to.be.undefined;
        expect(i18n.currentData).to.be.an('object');

    })

    it('#load(unexisting)', async () => {

        let i18n = I18nLoader;
        await i18n.load("ru");

        expect(i18n).not.to.be.undefined;
        expect(i18n.currentData.ru).to.be.undefined;

    })
    it('#translate()', async () => {

        let i18n = I18nLoader;
        await i18n.load();

        let translated = await i18n.translate('test');

        expect(i18n).not.to.be.undefined;
        expect(i18n.currentData).not.to.be.undefined;
        expect(translated).not.to.be.undefined;
        expect(translated).to.eq('asdf');

    })

    it('#unexisting.translate()', async () => {

        let i18n = I18nLoader;
        await i18n.load();

        let translated = await await i18n.translate('test2');

        expect(i18n).not.to.be.undefined;
        expect(i18n.currentData).not.to.be.undefined;
        expect(translated).not.to.be.undefined;

    })


})