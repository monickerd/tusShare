@echo off
:: ---------------------------------------------------------------------------
:: test-run.bat — full E2E test runner (Windows)
::
:: Usage:
::   test-run.bat                                              :: full suite
::   test-run.bat tests/e2e/groups/test_02_user_crud.py       :: single group
::   set HEADED=1 & test-run.bat                              :: show browser window
::   set SKIP_LDAP=1 & test-run.bat                           :: skip LDAP/OIDC groups
:: ---------------------------------------------------------------------------
setlocal enabledelayedexpansion

set COMPOSE_FILE=docker-compose.test.yml
set PROJECT_NAME=tusshare_test

:: ---- Tear down any leftover state ----
echo [test-run] Removing any previous test environment...
docker compose -f "%COMPOSE_FILE%" -p "%PROJECT_NAME%" down -v --remove-orphans 2>nul

:: ---- Build the app image ----
echo [test-run] Building application image...
docker compose -f "%COMPOSE_FILE%" -p "%PROJECT_NAME%" build app
if errorlevel 1 goto :fail

:: ---- Spin up environment ----
echo [test-run] Starting test environment...
docker compose -f "%COMPOSE_FILE%" -p "%PROJECT_NAME%" up -d
if errorlevel 1 goto :fail

:: ---- Wait for app to be healthy ----
echo [test-run] Waiting for app to be healthy...
set MAX_WAIT=120
set ELAPSED=0

:health_loop
docker inspect --format={{.State.Health.Status}} %PROJECT_NAME%_app 2>nul | findstr /i "healthy" >nul
if not errorlevel 1 goto :healthy
if %ELAPSED% geq %MAX_WAIT% (
    echo [test-run] ERROR: App did not become healthy within %MAX_WAIT%s
    docker compose -f "%COMPOSE_FILE%" -p "%PROJECT_NAME%" logs app
    goto :fail
)
timeout /t 3 /nobreak >nul
set /a ELAPSED=%ELAPSED%+3
goto :health_loop

:healthy
echo [test-run] App is healthy.

:: ---- Ensure test dependencies and Playwright browsers are installed ----
echo [test-run] Installing test dependencies...
pip install -r requirements-test.txt -q
python -m playwright install chromium --with-deps -q 2>nul || python -m playwright install chromium

:: ---- Determine which test arguments to pass ----
set PYTEST_ARGS=%*
if "%PYTEST_ARGS%"=="" set PYTEST_ARGS=tests/e2e/

:: Optional: skip LDAP/OIDC groups
if "%SKIP_LDAP%"=="1" (
    set PYTEST_ARGS=%PYTEST_ARGS% --ignore=tests/e2e/groups/test_09_ldap_integration.py --ignore=tests/e2e/groups/test_10_oidc_integration.py
    echo [test-run] Skipping LDAP/OIDC groups (SKIP_LDAP=1)
)

:: ---- Run the tests ----
echo [test-run] Running test suite: %PYTEST_ARGS%
set TEST_APP_URL=http://localhost:8001
if "%HEADED%"=="" (set TEST_HEADED=0) else (set TEST_HEADED=%HEADED%)
set TEST_PROJECT_NAME=%PROJECT_NAME%

python -m pytest %PYTEST_ARGS% --tb=short -v --no-header -p no:warnings -s 2>&1 | python -c "import sys; open('testoutput.txt','w',encoding='utf-8').write(sys.stdin.read())"
set EXIT_CODE=%errorlevel%
type testoutput.txt

:: ---- Teardown ----
echo [test-run] Tearing down test environment...
docker compose -f "%COMPOSE_FILE%" -p "%PROJECT_NAME%" down -v --remove-orphans 2>nul

:: ---- Report ----
if %EXIT_CODE%==0 (
    echo [test-run] All tests passed.
) else (
    echo [test-run] Tests failed ^(exit code %EXIT_CODE%^).
)

exit /b %EXIT_CODE%

:fail
echo [test-run] Setup failed.
docker compose -f "%COMPOSE_FILE%" -p "%PROJECT_NAME%" down -v --remove-orphans 2>nul
exit /b 1
