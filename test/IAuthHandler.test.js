import { expect } from 'chai';
import { IAuthHandler } from '../src';



describe('IAuthHandler', () => {

    it('#construct()', async () => {
        try {
            let elm = new IAuthHandler();
        } catch (err) {
            expect(err).not.to.be.undefined;
        }
    })
    it('#construct2()', async () => {
        try {
            class test extends IAuthHandler {
                check() {

                }
            }
            let elm = new test();
        } catch (err) {
            expect(err).not.to.be.undefined;
        }
    })



})