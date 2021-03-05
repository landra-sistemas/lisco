import { expect } from 'chai';
import cluster from 'cluster';
import { run_lisco, EventHandler, Server, Utils, ClusterServer } from '../src';


describe('EventHandler', () => {

    it('#simple()', async () => {


        var testString;

        EventHandler.on('test', function test({ str }) {
            testString = str;
        });

        EventHandler.emit('test', { str: 'asdf' })
        expect(testString).not.to.be.undefined;
        expect(testString).to.eq('asdf');
    })

    it('#clustered()', async () => {

        cluster.isMaster = true;
        cluster.isWorker = false;

        process.env.CLUSTERED = true;

        const server = new Server();
        await run_lisco(server);
        ClusterServer.start();

        var testString;

        EventHandler.on('test', function test({ str }) {
            testString = str;
            console.log(str)
        });

        try {
            EventHandler.emit('test', { str: 'asdf' })
        } catch (ex) {

        }
        // await Utils.sleep(3000);

        expect(testString).not.to.be.undefined;
        expect(testString).to.eq('asdf');
    });

    it('#clusterWorker()', async () => {


        cluster.isMaster = false;
        cluster.isWorker = true;


        var testString;

        EventHandler.on('test', function test({ str }) {
            testString = str;
            console.log(str)
        });

        try {
            EventHandler.emit('test', { str: 'asdf' })
        } catch (ex) {

        }
        // await Utils.sleep(3000);

        expect(testString).not.to.be.undefined;
        expect(testString).to.eq('asdf');
    });



})