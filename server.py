import asyncio
import hashlib
import hmac
import json
import os
import time
import urllib.parse
from aiohttp import web
import cloudinary
import cloudinary.uploader
import cloudinary.api
import base64

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
    """Verify Telegram Web App initData signature and return user dict or None."""
    try:
        parsed = dict(urllib.parse.parse_qsl(init_data, strict_parsing=True))
        received_hash = parsed.pop("hash", None)
        if not received_hash:
            return None

        data_check_string = "\n".join(
            f"{k}={v}" for k, v in sorted(parsed.items())
        )

        secret_key = hmac.new(
            b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256
        ).digest()

        expected_hash = hmac.new(
            secret_key, data_check_string.encode(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_hash, received_hash):
            return None

        # Check expiry (24h)
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

def require_admin(handler):
    async def wrapper(request):
        user = get_user_from_request(request)
        if not user or user.get("id") not in ALLOWED_ADMINS:
            return web.json_response({"error": "Forbidden"}, status=403)
        return await handler(request)
    return wrapper


import re
from aiohttp import ClientSession, CookieJar

PLANET_GPS_EMAIL = os.getenv("PLANET_GPS_EMAIL")
PLANET_GPS_PASSWORD = os.getenv("PLANET_GPS_PASSWORD")
PLANET_GPS_USER_ID = "272967"

_gps_session: ClientSession | None = None
_gps_token: str | None = None

async def planet_gps_login() -> bool:
    global _gps_session, _gps_token
    try:
        jar = CookieJar(unsafe=True)
        if _gps_session:
            await _gps_session.close()
        _gps_session = ClientSession(cookie_jar=jar)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        # GET the iframe login page
        login_url = "https://web.planetgps.com/loginpage/planetgps/login.aspx?language=en-us"
        async with _gps_session.get(login_url, headers=headers) as resp:
            html = await resp.text()

        print(f"Login iframe HTML: {html[:500]}")

        # Extract fields
        fields = {}
        for field in ["__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION"]:
            m = re.search(rf'id="{field}"[^>]*value="([^"]*)"', html)
            fields[field] = m.group(1) if m else ""

        print(f"Fields: {list(fields.keys())}, values len: {[len(v) for v in fields.values()]}")

        # Find input names for username/password
        import re as _re
        inputs = _re.findall(r'<input[^>]+>', html)
        print(f"All inputs: {inputs}")

        data = {
            **fields,
            "LType": "1",
            "txtUserName": PLANET_GPS_EMAIL,
            "txtAccountPassword": PLANET_GPS_PASSWORD,
            "btnLogin": "Log In",
        }

        async with _gps_session.post(
            login_url, data=data, headers=headers, allow_redirects=True
        ) as resp:
            final_url = str(resp.url)
            body = await resp.text()
            print(f"Post response URL: {final_url}")
            print(f"Post response body: {body[:300]}")
            m = re.search(r'[?&]p=([^&]+)', final_url)
            if m:
                _gps_token = m.group(1)
                return True

        return False
    except Exception as e:
        print(f"PlanetGPS login error: {e}")
        return False

async def handle_fleet(request: web.Request):
    user = get_user_from_request(request)
    print(f"Fleet request, user: {user}, headers: {dict(request.headers)}")
    if not user or user.get("id") not in ALLOWED_ADMINS:
        return web.json_response({"error": "Forbidden"}, status=403)

    global _gps_session, _gps_token

    if not _gps_token:
        ok = await planet_gps_login()
        if not ok:
            return web.json_response({"error": "PlanetGPS login failed"}, status=502)

    payload = {
        "UserID": int(PLANET_GPS_USER_ID),
        "isFirst": True,
        "TimeZones": "-4:00",
        "DeviceId": 0
    }
    headers = {
        "Content-Type": "application/json",
        "Referer": f"https://web.planetgps.com/IframeMap.aspx?id={PLANET_GPS_USER_ID}&n={PLANET_GPS_EMAIL}&m=Gaode2&p={_gps_token}",
        "Origin": "https://web.planetgps.com",
    }

    try:
        async with _gps_session.post(
            "https://web.planetgps.com/Ajax/DevicesAjax.asmx/GetDevicesByUserID",
            json=payload, headers=headers
        ) as resp:
            data = await resp.json(content_type=None)
            # Token expired — re-login next time
            if "d" not in data:
                _gps_token = None
                return web.json_response({"error": "Session expired"}, status=503)
            return web.json_response(data)
    except Exception as e:
        _gps_token = None
        return web.json_response({"error": str(e)}, status=500)

# ================== HELPERS ==================
def load_drivers() -> dict:
    if not os.path.exists(DATA_PATH):
        return {}
    with open(DATA_PATH, "r") as f:
        return json.load(f)

def get_driver_folder(driver_id: str, driver_name: str) -> str:
    name = driver_name.replace(" ", "_")
    return f"drivers/{driver_id}_{name}"

def list_driver_files(folder: str) -> list[dict]:
    try:
        result = cloudinary.api.resources(
            type="upload",
            prefix=folder + "/",
            max_results=100
        )
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

async def handle_drivers(request: web.Request):
    """GET /drivers — list all drivers with file counts."""
    user = get_user_from_request(request)
    if not user or user.get("id") not in ALLOWED_ADMINS:
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


async def handle_driver_files(request: web.Request):
    """GET /driver/{id}/files — list files for a specific driver."""
    user = get_user_from_request(request)
    if not user or user.get("id") not in ALLOWED_ADMINS:
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


async def handle_upload(request: web.Request):
    """POST /driver/{id}/upload — upload a file to driver's folder."""
    user = get_user_from_request(request)
    if not user or user.get("id") not in ALLOWED_ADMINS:
        return web.json_response({"error": "Forbidden"}, status=403)

    driver_id = request.match_info["id"]
    drivers = load_drivers()

    if driver_id not in drivers:
        return web.json_response({"error": "Driver not found"}, status=404)

    driver = drivers[driver_id]
    folder = get_driver_folder(driver_id, driver["name"])

    try:
        body = await request.json()
        image_b64 = body.get("image")  # base64 string
        doc_name = body.get("name", "document").strip().replace(" ", "_")

        if not image_b64:
            return web.json_response({"error": "No image provided"}, status=400)

        # Strip data URI prefix if present
        if "," in image_b64:
            image_b64 = image_b64.split(",", 1)[1]

        image_bytes = base64.b64decode(image_b64)

        timestamp = int(time.time())
        filename = f"{doc_name}_{timestamp}"

        result = cloudinary.uploader.upload(
            image_bytes,
            folder=folder,
            public_id=filename,
            resource_type="image"
        )

        return web.json_response({
            "success": True,
            "name": filename,
            "url": result["secure_url"],
            "public_id": result["public_id"],
        })

    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_me(request: web.Request):
    """GET /me — returns current user info (used by frontend to check admin status)."""
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    user = verify_telegram_init_data(init_data) if init_data else None

    if not user:
        return web.json_response({"error": "Unauthorized"}, status=401)

    return web.json_response({
        "id": user.get("id"),
        "name": user.get("first_name", ""),
        "is_admin": user.get("id") in ALLOWED_ADMINS,
    })


# ================== CORS MIDDLEWARE ==================
@web.middleware
async def cors_middleware(request, handler):
    if request.method == "OPTIONS":
        response = web.Response()
    else:
        response = await handler(request)

    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Telegram-Init-Data"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


# ================== APP ==================
def create_app() -> web.Application:
    app = web.Application(middlewares=[cors_middleware])
    app.router.add_get("/me", handle_me)
    app.router.add_get("/drivers", handle_drivers)
    app.router.add_get("/driver/{id}/files", handle_driver_files)
    app.router.add_post("/driver/{id}/upload", handle_upload)
    app.router.add_get("/api/fleet", handle_fleet)
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
