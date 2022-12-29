#!/usr/bin/env node

import yargs from "yargs/yargs";
import { hideBin } from "yargs/helpers";

import { exec } from "child_process";
import gulp from "gulp";
import path from "path";
import del from "del";
import fs from "fs";
import gulpif from "gulp-if";
import uglify_plugin from "gulp-uglify-es";

const { default: uglify } = uglify_plugin;

let currentdir = null;
let config = null;

const loadConfig = () => {
    currentdir = path.resolve(".");
    const cfgTxt = fs.readFileSync(`${currentdir}/package.json`);
    if (!config && cfgTxt) {
        config = JSON.parse(cfgTxt);
    }
};

gulp.task("clean", () => {
    console.log("Cleaning build directory");
    loadConfig();

    return del([currentdir + ((config && config.outputdir) || "/build")]);
});

gulp.task("compile", () => {
    console.log("Compiling project. Check build dir");
    loadConfig();

    const baseInput = [
        `src/**/**`,
        `controllers/**/**`,
        `views/**/**`,
        `i18n/**/**`,
        `migrations/**/**`,
        `node_modules/**/**`,
        "knexfile.js",
        `.env`,
        `.env.defaults`,
        `log4js.json`,
        `package.json`,
        `package-lock.json`,
        `index.js`,
        `run.js`,
    ];
    return gulp
        .src((config && config.include) || baseInput, { base: ".", dot: true, allowEmpty: true })
        .pipe(gulpif(["*.js", "**/**.js", "!bin/**/**", "!builded_modules/**/**", "!node_modules/**/**", "!*.json"], uglify()))
        .pipe(gulp.dest(currentdir + ((config && config.outputdir) || "/build")));
});

yargs(hideBin(process.argv))
    .scriptName("lisco")
    .usage(
        `Como usar: 
            $0 [options] `
    )
    .command(
        ["compile", "build"],
        "compiles application for production",
        () => {},
        () => gulp.series(gulp.task("clean"), gulp.task("compile"))()
    )
    .command(
        ["database", "db"],
        "manages knex for database interaction.",
        () => {},
        (yargs) => {
            const args = yargs._.filter((el) => el !== "database");

            console.log(args);
            exec(`knex ${args.join(" ")}`, (stdout, stderr) => {
                console.log(stdout);
                console.log(stderr);
            });
        }
    )
    .help("h")
    .alias("h", "help").argv;

//TODO add generators for new proyects
