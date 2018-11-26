echo off
set COMMAND=%1
set ADD_FLAGS=
set filename=%0
SHIFT

IF "%COMMAND%"=="start" (
set ADD_FLAGS=--no-reject-unauthorized
set NODE_TLS_REJECT_UNAUTHORIZED=0
)
for %%F in (%filename%) do set dirname=%%~dpF


set _tail=%*
call set _tail=%%_tail:*%1=%%
echo %_tail%

call %dirname%solid.cmd %COMMAND% %ADD_FLAGS% %_tail%