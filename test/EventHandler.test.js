import { expect } from 'chai';
import cluster from 'cluster';
import { EventHandler, App } from '../src';


describe('EventHandler', () => {

    it('#simple()', async () => {

        let events = new EventHandler();

        var testString;

        events.on('test', function test({ str }) {
            testString = str;
        });

        events.emit('test', { str: 'asdf' })
        expect(testString).not.to.be.undefined;
        expect(testString).to.eq('asdf');
    })

    it('#clustered()', async () => {

        cluster.isMaster = true;
        cluster.isWorker = false;

        process.env.CLUSTERED = true;

        await App.init();
        App.server.start();

        var testString;

        App.events.on('test', function test({ str }) {
            testString = str;
            console.log(str)
        });

        try {
            App.events.emit('test', { str: 'asdf' })
        } catch (ex) {

        }
        // await Utils.sleep(3000);

        expect(testString).not.to.be.undefined;
        expect(testString).to.eq('asdf');
    });

    it('#clusterWorker()', async () => {


        cluster.isMaster = false;
        cluster.isWorker = true;

        let events = new EventHandler();

        var testString;

        events.on('test', function test({ str }) {
            testString = str;
            console.log(str)
        });

        try {
            events.emit('test', { str: 'asdf' })
        } catch (ex) {

        }
        // await Utils.sleep(3000);

        expect(testString).not.to.be.undefined;
        expect(testString).to.eq('asdf');
    });



})