import { expect } from 'chai';
import { IUserDao } from '../src';


describe('IUserDao', () => {

    it('#construct()', async () => {
        try {
            let elm = new IUserDao();
        } catch (err) {
            expect(err).not.to.be.undefined;
        }
    })



})