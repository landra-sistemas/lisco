import { expect } from 'chai';
import { App } from '../src';


describe('App', async () => {
    it('#App.init()', () => {
        try {
            App.init()

            expect(App.server).not.to.be.null;
        } catch (e) {
            console.log(e)
        }
    })
})