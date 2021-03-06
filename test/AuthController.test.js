import { expect } from 'chai';
import { AuthController } from '../src';


describe('AuthController', async () => {
    it('#configure()', () => {
        let auth = new AuthController([], {
            UserDao: {
                findByUsername: () => { }
            }
        });

        auth.configure();

        expect(auth).not.to.be.null;
    })
    it('#check#public()', () => {

        let auth = new AuthController(['/test'], {
            UserDao: {
                findByUsername: () => { }
            }
        });
        expect(auth).not.to.be.null;

        let checked = false;
        let code = null;

        const fakeResponse = {
            status: (status) => {
                code = status;
                return {
                    json: () => { }
                }
            }
        };
        const fakeRequest = {
            headers: { authorization: "" },
            url: 'http://asdfasd/test'
        }


        auth.check(fakeRequest, fakeResponse, function () {
            checked = true;
        })

        expect(checked).to.eq(true);


    })
    it('#check#private#invalid()', async () => {

        let auth = new AuthController(['/test'], {
            UserDao: {
                findByUsername: () => { }
            },
            check: () => { return false; }
        });
        expect(auth).not.to.be.null;


        let checked = false;
        let code = null;

        const fakeResponse = {
            status: (status) => {
                code = status;
                return {
                    json: () => { }
                }
            }
        };
        const fakeRequest = {
            headers: { authorization: "" },
            url: 'http://asdfasd/testPrivate'
        }

        await auth.check(fakeRequest, fakeResponse, function () {
            checked = true;
        })

        expect(checked).to.eq(false);
        expect(code).to.eq(403);

    })


    it('#check#private#valid()', async () => {

        let auth = new AuthController(['/test'], {
            UserDao: {
                findByUsername: () => { }
            },
            check: () => { return true; }
        });
        expect(auth).not.to.be.null;


        let checked = false;
        let code = null;

        const fakeResponse = {
            status: (status) => {
                code = status;
                return {
                    json: () => { }
                }
            }
        };
        const fakeRequest = {
            headers: { authorization: "" },
            url: 'http://asdfasd/testPrivate'
        }

        await auth.check(fakeRequest, fakeResponse, function () {
            checked = true;
        })

        expect(checked).to.eq(true);
        expect(code).to.be.null;

    })



    it('#login#invalid()', async () => {

        let auth = new AuthController(['/test'], {
            UserDao: {
                findByUsername: () => { }
            },
            authorize: () => { return false; }
        });
        expect(auth).not.to.be.null;


        let code = null;
        let data = null;

        const fakeResponse = {
            status: (status) => {
                code = status;
                return {
                    json: (resp) => { data = resp }
                }
            }
        };
        const fakeRequest = {
            headers: { authorization: "" },
            body: {
                username: "asdf",
                password: "asdf"
            }
        }

        await auth.loginPost(fakeRequest, fakeResponse)

        expect(code).not.to.eq(200);
        expect(data).not.to.be.null;

    })
    it('#login#valid()', async () => {

        let auth = new AuthController(['/test'], {
            UserDao: {
                findByUsername: () => { }
            },
            authorize: () => { return true; }
        });
        expect(auth).not.to.be.null;


        let code = null;
        let data = null;

        const fakeResponse = {
            status: (status) => {
                code = status;
                return {
                    json: (resp) => { data = resp }
                }
            }
        };
        const fakeRequest = {
            headers: { authorization: "" },
            body: {
                username: "asdf",
                password: "asdf"
            }
        }

        await auth.loginPost(fakeRequest, fakeResponse)

        expect(code).to.eq(200);
        expect(data).not.to.be.null;

    })


    it('#logout()', async () => {

        let auth = new AuthController(['/test'], {
            UserDao: {
                findByUsername: () => { }
            },
            logout: () => { return true; }
        });
        expect(auth).not.to.be.null;


        let code = null;
        let data = null;

        const fakeResponse = {
            status: (status) => {
                code = status;
                return {
                    json: (resp) => { data = resp }
                }
            }
        };
        const fakeRequest = {
            headers: { authorization: "" },
            session: {
                username: "asdf",
                password: "asdf"
            }
        }

        await auth.logout(fakeRequest, fakeResponse)

        expect(code).to.eq(200);
        expect(data).not.to.be.null;

    })



})