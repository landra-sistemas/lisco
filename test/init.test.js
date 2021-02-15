import { expect } from 'chai';
import { run_lisco, Server } from '../src';


describe('init', async () => {
    it('#run_lisco()', () => {
        try {
            const server = new Server();
            run_lisco(server)

            expect(server).not.to.be.null;
        } catch (e) {
            console.log(e)
        }
    })
})