0</* :{
        @echo off
        node %~f0 %*
        exit /b %errorlevel%
:} */0;

//process.stdin.setRawMode(true);
//process.stdin.resume();
//process.stdin.on('data', process.exit.bind(process, 0));

const startCli = require('./lib/cli')
startCli()
