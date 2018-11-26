0</* :{
        @echo off
        node %~f0 %*
        exit /b %errorlevel%
:} */0;

const startCli = require('./lib/cli')
startCli()
