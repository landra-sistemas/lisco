import { expect } from 'chai';
import { CookieAuthHandler } from '../src';

const UserDao = function () {
    this.findByUsername = () => ({ username: "admin", password: "ee7646601f245dc9d098678949753e2e" })
}



describe('CookieAuthHandler', () => {


    it('#constructs()', async () => {
        try {
            const handler = new CookieAuthHandler();
        } catch (ex) {
            expect(ex).not.to.be.undefined;
        }
    })

    it('#check#invalid()', async () => {
        const handler = new CookieAuthHandler(UserDao);

        let result = await handler.check({ headers: { authorization: "" } });

        expect(result).not.to.be.null;
        expect(result).to.be.false;
    })

    it('#check#invalid2()', async () => {
        const handler = new CookieAuthHandler(UserDao);

        let result = await handler.check({ headers: { authorization: "Basic YWRtaW46YWRtaW42=" } });

        expect(result).not.to.be.null;
        expect(result).to.be.false;
    })

    it('#check#valid()', async () => {
        const handler = new CookieAuthHandler(UserDao);

        let result = handler.check({ headers: { authorization: "Basic YWRtaW46YWRtaW4=" } });

        expect(result).not.to.be.null;
        expect(result).not.to.be.false;
    })


    it('#validate()', async () => {
        const handler = new CookieAuthHandler(UserDao);

        let result = await handler.validate({}, "admin", "admin");

        expect(result).not.to.be.null;
    })



})