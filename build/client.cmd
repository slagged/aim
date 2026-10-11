@echo off
if not defined VS71COMNTOOLS (
    echo Set VS71COMNTOOLS to the Visual Studio 2003 Common7\Tools directory.
    exit /b 1
)
call "%VS71COMNTOOLS%vsvars32.bat"
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist builds mkdir builds
set "AIMCMP_CFLAGS=/O1 /MD /EHsc /GS"
if exist aimcmp-flags.txt set /p AIMCMP_CFLAGS=<aimcmp-flags.txt
for %%F in (oscore AIMToday oscres AIM_xmlp Xpcs Xprt) do (
    lib /nologo /machine:x86 /def:deps\%%F.def /out:builds\%%F.lib
    if errorlevel 1 exit /b 1
)
for %%F in (guid_equal file_time_before allocate_zeroed registry_writable components registration crash startup) do (
    cl /nologo /c %AIMCMP_CFLAGS% /I"src" /FI"import_aliases.h" /Fobuilds\%%F.obj "src\%%F.cpp"
    if errorlevel 1 exit /b 1
)
link /nologo /subsystem:windows /machine:x86 /base:0x400000 /opt:noref /out:builds\aim.exe /map:builds\aim.map builds\guid_equal.obj builds\file_time_before.obj builds\allocate_zeroed.obj builds\registry_writable.obj builds\components.obj builds\registration.obj builds\crash.obj builds\startup.obj deps\aim.res builds\oscore.lib builds\AIMToday.lib builds\oscres.lib builds\AIM_xmlp.lib builds\Xpcs.lib builds\Xprt.lib kernel32.lib user32.lib advapi32.lib version.lib shell32.lib ole32.lib oleaut32.lib uuid.lib
if errorlevel 1 exit /b 1
echo Build complete. No candidate was executed.
