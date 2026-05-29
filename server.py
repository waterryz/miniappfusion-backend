import asyncio
import hashlib
import hmac
import json
import os
import time
import urllib.parse
from aiohttp import web, ClientSession, CookieJar
import cloudinary
import cloudinary.uploader
import cloudinary.api
import base64
from yarl import URL
from datetime import datetime, timezone

# ================== CONFIG ==================
BOT_TOKEN = os.getenv("BOT_TOKEN")
ALLOWED_ADMINS = {5348697217, 547004364}
DATA_PATH = "/data/drivers.json"

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

# ================== AUTH ==================
def verify_telegram_init_data(init_data: str) -> dict | None:
    try:
        parsed = dict(urllib.parse.parse_qsl(init_data, strict_parsing=True))
        received_hash = parsed.pop("hash", None)
        if not received_hash:
            return None
        data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(parsed.items()))
        secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        expected_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_hash, received_hash):
            return None
        auth_date = int(parsed.get("auth_date", 0))
        if time.time() - auth_date > 86400:
            return None
        user = json.loads(parsed.get("user", "{}"))
        return user
    except Exception:
        return None

def get_user_from_request(request: web.Request) -> dict | None:
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    if not init_data:
        return None
    return verify_telegram_init_data(init_data)

def is_admin_request(request: web.Request) -> bool:
    user = get_user_from_request(request)
    return bool(user and user.get("id") in ALLOWED_ADMINS)

# ================== HELPERS ==================
def load_drivers() -> dict:
    if not os.path.exists(DATA_PATH):
        return {}
    with open(DATA_PATH, "r") as f:
        return json.load(f)

def save_drivers(data: dict):
    os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
    with open(DATA_PATH, "w") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def get_driver_folder(driver_id: str, driver_name: str) -> str:
    name = driver_name.replace(" ", "_")
    return f"drivers/{driver_id}_{name}"

def list_driver_files(folder: str) -> list[dict]:
    try:
        result = cloudinary.api.resources(type="upload", prefix=folder + "/", max_results=100)
        files = []
        for r in result.get("resources", []):
            files.append({
                "public_id": r["public_id"],
                "name": r["public_id"].split("/")[-1],
                "url": r["secure_url"],
                "created_at": r.get("created_at", ""),
                "format": r.get("format", ""),
                "bytes": r.get("bytes", 0),
            })
        return files
    except Exception:
        return []

# ================== MILEAGE HELPER ==================
async def get_monthly_mileage(device_id: str) -> str | None:
    """Fetch mileage for current month for a specific device from PlanetGPS report."""
    global _gps_session, _gps_cookies
    if not _gps_cookies:
        ok = await planet_gps_login_playwright()
        if not ok:
            return None
        jar = CookieJar(unsafe=True)
        _gps_session = ClientSession(cookie_jar=jar)
        jar.update_cookies(_gps_cookies, response_url=URL("https://web.planetgps.com"))

    now = datetime.now(timezone.utc)
    start = f"{now.year}-{now.month:02d}-01 00:00"
    end = f"{now.year}-{now.month:02d}-{now.day:02d} 23:59"

    payload = json.dumps({
        "UserID": 272967,
        "TimeZones": "5:00",
        "StartDates": start,
        "EndDates": end,
        "DeviceID": 0
    })
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Referer": "https://web.planetgps.com/Report/Report.aspx",
        "Origin": "https://web.planetgps.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "X-Requested-With": "XMLHttpRequest",
    }
    try:
        async with _gps_session.post(
            "https://web.planetgps.com/Ajax/ReportAjax.asmx/GetReportOverview",
            data=payload, headers=headers
        ) as resp:
            data = await resp.json(content_type=None)
            if "d" not in data or not data["d"]:
                return None
            import re as _re
            raw = data["d"]
            fixed = _re.sub(r'([{,])\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":', raw)
            fixed = _re.sub(r":\s*'([^']*)'", r':"\1"', fixed)
            parsed = json.loads(fixed)
            rows = parsed.get("reports") or parsed.get("reportList") or parsed.get("devices") or parsed.get("list") or []
            if rows:
                # Find row matching device_id by cross-referencing fleet data
                # First try exact device id match
                row = next((r for r in rows if str(r.get("deviceID") or r.get("DeviceID") or "") == str(device_id)), None)
                # If not found, get fleet data to match by name
                if not row:
                    try:
                        fleet_payload = '{"UserID":272967,"isFirst":true,"TimeZones":"5:00","DeviceID":0}'
                        fleet_headers = {
                            "Content-Type": "application/json",
                            "Referer": "https://web.planetgps.com/Monitor.aspx",
                            "Origin": "https://web.planetgps.com",
                            "User-Agent": "Mozilla/5.0",
                            "X-Requested-With": "XMLHttpRequest",
                        }
                        async with _gps_session.post(
                            "https://web.planetgps.com/Ajax/DevicesAjax.asmx/GetDevicesByUserID",
                            data=fleet_payload, headers=fleet_headers
                        ) as fr:
                            fdata = await fr.json(content_type=None)
                            if fdata.get("d"):
                                fraw = fdata["d"]
                                ffixed = _re.sub(r'([{,])\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":', fraw)
                                ffixed = _re.sub(r":\s*'([^']*)'", r':"\1"', ffixed)
                                fdevices = json.loads(ffixed).get("devices", [])
                                device = next((d for d in fdevices if str(d.get("id", "")) == str(device_id)), None)
                                if device:
                                    dname = device.get("name", "").lower()
                                    row = next((r for r in rows if r.get("name", "").lower() == dname), None)
                    except Exception as fe:
                        print(f"Fleet lookup error: {fe}")
                if not row:
                    row = rows[0]
                mileage = row.get("distance") or row.get("mileage") or row.get("Mileage") or "—"
                return str(mileage)
            return "0"
    except Exception as e:
        print(f"Mileage fetch error: {e}")
        return None

# ================== ROUTES ==================

async def handle_me(request: web.Request):
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    user = verify_telegram_init_data(init_data) if init_data else None
    if not user:
        return web.json_response({"error": "Unauthorized"}, status=401)
    return web.json_response({
        "id": user.get("id"),
        "name": user.get("first_name", ""),
        "is_admin": user.get("id") in ALLOWED_ADMINS,
    })


async def handle_drivers(request: web.Request):
    if not is_admin_request(request):
        return web.json_response({"error": "Forbidden"}, status=403)
    drivers = load_drivers()
    result = []
    for uid, d in drivers.items():
        folder = get_driver_folder(uid, d["name"])
        files = list_driver_files(folder)
        result.append({
            "id": uid,
            "name": d["name"],
            "car_model": d.get("car_model", ""),
            "car_number": d.get("car_number", ""),
            "tariff": d.get("tariff", ""),
            "planet_gps_device_id": d.get("planet_gps_device_id", ""),
            "file_count": len(files),
        })
    return web.json_response(result)


async def handle_driver_get(request: web.Request):
    if not is_admin_request(request):
        return web.json_response({"error": "Forbidden"}, status=403)
    driver_id = request.match_info["id"]
    drivers = load_drivers()
    if driver_id not in drivers:
        return web.json_response({"error": "Driver not found"}, status=404)
    driver = drivers[driver_id]
    folder = get_driver_folder(driver_id, driver["name"])
    files = list_driver_files(folder)
    return web.json_response({
        "driver": {
            "id": driver_id,
            "name": driver["name"],
            "car_model": driver.get("car_model", ""),
            "car_number": driver.get("car_number", ""),
            "tariff": driver.get("tariff", ""),
            "planet_gps_device_id": driver.get("planet_gps_device_id", ""),
        },
        "files": files,
    })


async def handle_driver_add(request: web.Request):
    if not is_admin_request(request):
        return web.json_response({"error": "Forbidden"}, status=403)
    try:
        body = await request.json()
        driver_id = str(body.get("id", "")).strip()
        name = body.get("name", "").strip()
        car_model = body.get("car_model", "").strip()
        car_number = body.get("car_number", "").strip()
        tariff = body.get("tariff", "").strip()
        planet_gps_device_id = body.get("planet_gps_device_id", "").strip()
        if not all([driver_id, name, car_model, car_number, tariff]):
            return web.json_response({"error": "All fields required"}, status=400)
        if not driver_id.isdigit():
            return web.json_response({"error": "ID must be numeric"}, status=400)
        drivers = load_drivers()
        if driver_id in drivers:
            return web.json_response({"error": "Driver with this ID already exists"}, status=409)
        drivers[driver_id] = {
            "name": name,
            "car_model": car_model,
            "car_number": car_number,
            "tariff": tariff,
            "planet_gps_device_id": planet_gps_device_id,
        }
        save_drivers(drivers)
        return web.json_response({"success": True, "id": driver_id})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_driver_update(request: web.Request):
    """Update driver fields (admin only). Used to set planet_gps_device_id on existing drivers."""
    if not is_admin_request(request):
        return web.json_response({"error": "Forbidden"}, status=403)
    driver_id = request.match_info["id"]
    drivers = load_drivers()
    if driver_id not in drivers:
        return web.json_response({"error": "Driver not found"}, status=404)
    try:
        body = await request.json()
        updatable = ["car_model", "car_number", "tariff", "planet_gps_device_id"]
        for field in updatable:
            if field in body:
                drivers[driver_id][field] = str(body[field]).strip()
        save_drivers(drivers)
        return web.json_response({"success": True})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_driver_delete(request: web.Request):
    if not is_admin_request(request):
        return web.json_response({"error": "Forbidden"}, status=403)
    driver_id = request.match_info["id"]
    drivers = load_drivers()
    if driver_id not in drivers:
        return web.json_response({"error": "Driver not found"}, status=404)
    driver = drivers[driver_id]
    folder = get_driver_folder(driver_id, driver["name"])
    try:
        cloudinary.api.delete_resources_by_prefix(folder + "/")
        try:
            cloudinary.api.delete_folder(folder)
        except Exception:
            pass
    except Exception as e:
        print(f"Warn: couldn't delete Cloudinary resources: {e}")
    del drivers[driver_id]
    save_drivers(drivers)
    return web.json_response({"success": True})


async def handle_upload(request: web.Request):
    if not is_admin_request(request):
        return web.json_response({"error": "Forbidden"}, status=403)
    driver_id = request.match_info["id"]
    drivers = load_drivers()
    if driver_id not in drivers:
        return web.json_response({"error": "Driver not found"}, status=404)
    driver = drivers[driver_id]
    folder = get_driver_folder(driver_id, driver["name"])
    try:
        body = await request.json()
        image_b64 = body.get("image")
        doc_name = body.get("name", "document").strip().replace(" ", "_")
        if not image_b64:
            return web.json_response({"error": "No image provided"}, status=400)
        if "," in image_b64:
            image_b64 = image_b64.split(",", 1)[1]
        image_bytes = base64.b64decode(image_b64)
        timestamp = int(time.time())
        filename = f"{doc_name}_{timestamp}"
        result = cloudinary.uploader.upload(image_bytes, folder=folder, public_id=filename, resource_type="image")
        return web.json_response({"success": True, "name": filename, "url": result["secure_url"], "public_id": result["public_id"]})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_file_delete(request: web.Request):
    if not is_admin_request(request):
        return web.json_response({"error": "Forbidden"}, status=403)
    try:
        body = await request.json()
        public_id = body.get("public_id", "").strip()
        if not public_id:
            return web.json_response({"error": "public_id required"}, status=400)
        cloudinary.uploader.destroy(public_id, resource_type="image")
        return web.json_response({"success": True})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


# ================== DRIVER SELF-VIEW ==================

async def handle_driver_me(request: web.Request):
    """
    Driver-facing endpoint. Returns own profile + documents + monthly mileage.
    Auth: any valid Telegram user whose ID exists in drivers.json.
    """
    user = get_user_from_request(request)
    if not user:
        return web.json_response({"error": "Unauthorized"}, status=401)

    user_id = str(user.get("id", ""))
    drivers = load_drivers()

    if user_id not in drivers:
        return web.json_response({"error": "Not registered"}, status=403)

    driver = drivers[user_id]
    folder = get_driver_folder(user_id, driver["name"])
    files = list_driver_files(folder)

    # Fetch mileage if device_id is set
    mileage = None
    device_id = driver.get("planet_gps_device_id", "")
    if device_id:
        mileage = await get_monthly_mileage(device_id)

    now = datetime.now(timezone.utc)
    month_label = now.strftime("%B %Y")

    return web.json_response({
        "driver": {
            "id": user_id,
            "name": driver["name"],
            "car_model": driver.get("car_model", ""),
            "car_number": driver.get("car_number", ""),
            "tariff": driver.get("tariff", ""),
        },
        "files": files,
        "mileage": {
            "value": mileage,
            "month": month_label,
            "has_gps": bool(device_id),
        }
    })


# ================== MILEAGE ENDPOINT ==================

async def handle_mileage(request: web.Request):
    """GET /api/mileage/{device_id} — monthly mileage for a specific device."""
    device_id = request.match_info["device_id"]
    if not device_id:
        return web.json_response({"mileage": None})
    mileage = await get_monthly_mileage(device_id)
    return web.json_response({"mileage": mileage})


# ================== FLEET ==================
from playwright.async_api import async_playwright

PLANET_GPS_EMAIL = os.getenv("PLANET_GPS_EMAIL", "alexyss.waterry@icloud.com")
PLANET_GPS_PASSWORD = os.getenv("PLANET_GPS_PASSWORD", "")
PLANET_GPS_USER_ID = "272967"

_gps_session = None
_gps_cookies = None
_playwright = None
_browser = None

async def planet_gps_login_playwright() -> bool:
    global _playwright, _browser, _gps_cookies, _gps_session
    try:
        print("Starting Playwright login...")
        _playwright = await async_playwright().start()
        _browser = await _playwright.chromium.launch(headless=True)
        context = await _browser.new_context()
        page = await context.new_page()

        await page.goto("https://web.planetgps.com/index.aspx", wait_until="domcontentloaded")
        await page.wait_for_timeout(2000)
        
        frame = page.frame_locator("iframe#ifm")
        await frame.locator("#changBar0").click()
        await page.wait_for_timeout(500)
        await frame.locator('input[name="txtUserName"]').fill(PLANET_GPS_EMAIL)
        await frame.locator('input[name="txtAccountPassword"]').fill(PLANET_GPS_PASSWORD)
        
        async with page.expect_navigation(wait_until="domcontentloaded", timeout=15000):
            await frame.locator('input[name="btnLogin"]').click()

        final_url = page.url
        print(f"Playwright final URL: {final_url}")

        cookies = await context.cookies()
        _gps_cookies = {c["name"]: c["value"] for c in cookies}
        print(f"Got cookies: {list(_gps_cookies.keys())}")

        await context.close()
        return "Monitor.aspx" in final_url or "p=" in final_url

    except Exception as e:
        print(f"Playwright login error: {e}")
        return False


async def handle_fleet(request: web.Request):
    if not is_admin_request(request):
        return web.json_response({"error": "Forbidden"}, status=403)

    global _gps_session, _gps_cookies
    if not _gps_cookies:
        ok = await planet_gps_login_playwright()
        if not ok:
            return web.json_response({"error": "PlanetGPS login failed"}, status=502)

    if not _gps_session:
        jar = CookieJar(unsafe=True)
        _gps_session = ClientSession(cookie_jar=jar)
        jar.update_cookies(_gps_cookies, response_url=URL("https://web.planetgps.com"))

    payload = '{"UserID":272967,"isFirst":true,"TimeZones":"5:00","DeviceID":0}'
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Referer": "https://web.planetgps.com/Monitor.aspx",
        "Origin": "https://web.planetgps.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "X-Requested-With": "XMLHttpRequest",
    }
    try:
        async with _gps_session.post(
            "https://web.planetgps.com/Ajax/DevicesAjax.asmx/GetDevicesByUserID",
            data=payload, headers=headers
        ) as resp:
            data = await resp.json(content_type=None)
            print(f"Fleet response: {str(data)[:200]}")
            if "d" not in data or not data["d"]:
                _gps_cookies = None
                _gps_session = None
                return web.json_response({"error": "Session expired"}, status=503)
            return web.json_response(data)
    except Exception as e:
        _gps_cookies = None
        _gps_session = None
        return web.json_response({"error": str(e)}, status=500)


async def handle_fleet_report(request: web.Request):
    if not is_admin_request(request):
        return web.json_response({"error": "Forbidden"}, status=403)

    params = request.rel_url.query
    start = params.get("from", "")
    end = params.get("to", "")
    if not start or not end:
        return web.json_response({"error": "Missing from/to"}, status=400)

    global _gps_session, _gps_cookies
    if not _gps_cookies:
        ok = await planet_gps_login_playwright()
        if not ok:
            return web.json_response({"error": "PlanetGPS login failed"}, status=502)
        jar = CookieJar(unsafe=True)
        _gps_session = ClientSession(cookie_jar=jar)
        jar.update_cookies(_gps_cookies, response_url=URL("https://web.planetgps.com"))

    payload = f'{{"UserID":272967,"TimeZones":"5:00","StartDates":"{start}","EndDates":"{end}","DeviceID":0}}'
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Referer": "https://web.planetgps.com/Report/Report.aspx?id=272967&deviceid=0&randon=21896",
        "Origin": "https://web.planetgps.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "X-Requested-With": "XMLHttpRequest",
    }
    try:
        async with _gps_session.post(
            "https://web.planetgps.com/Ajax/ReportAjax.asmx/GetReportOverview",
            data=payload, headers=headers
        ) as resp:
            data = await resp.json(content_type=None)
            print(f"Report response: {str(data)[:300]}")
            if "d" not in data:
                _gps_cookies = None
                _gps_session = None
                return web.json_response({"error": "Session expired"}, status=503)
            return web.json_response(data)
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_fleet_report_excel(request: web.Request):
    if not is_admin_request(request):
        return web.json_response({"error": "Forbidden"}, status=403)

    params = request.rel_url.query
    start = params.get("from", "")
    end = params.get("to", "")
    if not start or not end:
        return web.json_response({"error": "Missing from/to"}, status=400)

    global _gps_session, _gps_cookies
    if not _gps_cookies:
        ok = await planet_gps_login_playwright()
        if not ok:
            return web.json_response({"error": "Login failed"}, status=502)
        jar = CookieJar(unsafe=True)
        _gps_session = ClientSession(cookie_jar=jar)
        jar.update_cookies(_gps_cookies, response_url=URL("https://web.planetgps.com"))

    report_url = f"https://web.planetgps.com/Report/Report.aspx?id={PLANET_GPS_USER_ID}&deviceid=0&randon=12345"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Referer": report_url,
    }
    import re as _re
    async with _gps_session.get(report_url, headers=headers) as resp:
        html = await resp.text()

    fields = {}
    for field in ["__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION"]:
        m = _re.search(rf'id="{field}"[^>]*value="([^"]*)"', html)
        fields[field] = m.group(1) if m else ""

    data = {
        **fields,
        "beginTime": start,
        "endTime": end,
        "btnToExcel": "To Excel",
        "hidUserID": PLANET_GPS_USER_ID,
        "hidTimeZone": "5:00",
        "hidDeviceID": "0",
    }

    post_headers = {
        **headers,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        async with _gps_session.post(report_url, data=data, headers=post_headers) as resp:
            content = await resp.read()
            return web.Response(
                body=content,
                content_type="application/vnd.ms-excel",
                headers={"Content-Disposition": f'attachment; filename="report_{start[:10]}_{end[:10]}.xls"'}
            )
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


# ================== CORS MIDDLEWARE ==================
@web.middleware
async def cors_middleware(request, handler):
    if request.method == "OPTIONS":
        response = web.Response()
    else:
        response = await handler(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Telegram-Init-Data"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
    return response


def create_app() -> web.Application:
    app = web.Application(middlewares=[cors_middleware])
    app.router.add_get("/me", handle_me)
    app.router.add_get("/drivers", handle_drivers)
    app.router.add_post("/drivers", handle_driver_add)
    app.router.add_get("/driver/me", handle_driver_me)          # NEW: driver self-view
    app.router.add_get("/driver/{id}", handle_driver_get)
    app.router.add_patch("/driver/{id}", handle_driver_update)  # NEW: update device_id
    app.router.add_delete("/driver/{id}", handle_driver_delete)
    app.router.add_post("/driver/{id}/upload", handle_upload)
    app.router.add_delete("/file", handle_file_delete)
    app.router.add_get("/api/fleet", handle_fleet)
    app.router.add_get("/api/mileage/{device_id}", handle_mileage)
    app.router.add_get("/api/fleet/report", handle_fleet_report)
    app.router.add_get("/api/fleet/report/excel", handle_fleet_report_excel)
    options_paths = [
        "/me", "/drivers", "/driver/me", "/driver/{id}",
        "/driver/{id}/upload", "/file", "/api/fleet",
        "/api/mileage/{device_id}",
        "/api/fleet/report", "/api/fleet/report/excel"
    ]
    for path in options_paths:
        app.router.add_options(path, lambda r: web.Response())
    return app


async def start_server():
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.getenv("PORT", 8080))
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    print(f"API server running on port {port}")
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(start_server())
