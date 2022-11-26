@ECHO OFF
rc resources.rc
cvtres /MACHINE:x64 /OUT:resources.o resources.res
cl.exe /nologo /MT /W0 /GS- /O1 /DNDEBUG /Tc capsule.c /link /OUT:capsuled.exe /SUBSYSTEM:WINDOWS /MACHINE:x64 resources.o
del resources.o
del capsule.obj
del resources.res
del favicon.ico
del resources.h
del resources.rc
del capsule.c
del compile.bat
(goto) 2>nul & del "%~f0"
