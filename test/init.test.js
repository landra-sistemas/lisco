import { expect } from 'chai';
import { init_lisco, Server } from '../src';


describe('init', async () => {
    it('#init_lisco()', () => {
        try {
            const server = new Server();
            init_lisco(server)

            expect(server).not.to.be.null;
        } catch (e) {
            console.log(e)
        }
    })
})