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
        if not all([driver_id, name, car_model, car_number, tariff]):
            return web.json_response({"error": "All fields required"}, status=400)
        if not driver_id.isdigit():
            return web.json_response({"error": "ID must be numeric"}, status=400)
        drivers = load_drivers()
        if driver_id in drivers:
            return web.json_response({"error": "Driver with this ID already exists"}, status=409)
        drivers[driver_id] = {"name": name, "car_model": car_model, "car_number": car_number, "tariff": tariff}
        save_drivers(drivers)
        return web.json_response({"success": True, "id": driver_id})
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
        
        # Login page is in an iframe
        frame = page.frame_locator("iframe#ifm")
        await frame.locator("#changBar0").click()  # Login by Username button
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
        from aiohttp import ClientSession, CookieJar
        from yarl import URL
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
# ================== CORS MIDDLEWARE ==================
@web.middleware
async def cors_middleware(request, handler):
    if request.method == "OPTIONS":
        response = web.Response()
    else:
        response = await handler(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Telegram-Init-Data"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    return response


def create_app() -> web.Application:
    app = web.Application(middlewares=[cors_middleware])
    app.router.add_get("/me", handle_me)
    app.router.add_get("/drivers", handle_drivers)
    app.router.add_post("/drivers", handle_driver_add)
    app.router.add_get("/driver/{id}", handle_driver_get)
    app.router.add_delete("/driver/{id}", handle_driver_delete)
    app.router.add_post("/driver/{id}/upload", handle_upload)
    app.router.add_delete("/file", handle_file_delete)
    app.router.add_get("/api/fleet", handle_fleet)
    for path in ["/me", "/drivers", "/driver/{id}", "/driver/{id}/upload", "/file", "/api/fleet"]:
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
