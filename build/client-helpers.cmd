@echo off
if not defined VS71COMNTOOLS (
    echo Set VS71COMNTOOLS to the Visual Studio 2003 Common7\Tools directory.
    exit /b 1
)
call "%VS71COMNTOOLS%vsvars32.bat"
if errorlevel 1 exit /b 1
if not exist "%~dp0..\aimcmp\builds\client-helpers" mkdir "%~dp0..\aimcmp\builds\client-helpers"
pushd "%~dp0..\aimcmp\builds\client-helpers"
for %%F in (guid_equal file_time_before allocate_zeroed registry_writable) do (
    cl /nologo /c /O1 /MD /EHsc /GS /Fo%%F.obj "%~dp0..\src\client\%%F.cpp"
    if errorlevel 1 exit /b 1
)
popd
