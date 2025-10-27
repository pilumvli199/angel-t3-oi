import os
import time
import threading
import logging
from flask import Flask, jsonify
import pyotp
import requests
from datetime import datetime, timedelta

# ---- SmartAPI import ----
SmartConnect = None
try:
    from SmartApi import SmartConnect as _SC
    SmartConnect = _SC
    logging.info("SmartConnect imported successfully!")
except Exception as e:
    logging.error(f"Failed to import SmartConnect: {e}")
    SmartConnect = None

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('angel-option-chain-bot')

# Load config from env
API_KEY = os.getenv('SMARTAPI_API_KEY')
CLIENT_ID = os.getenv('SMARTAPI_CLIENT_ID')
PASSWORD = os.getenv('SMARTAPI_PASSWORD')
TOTP_SECRET = os.getenv('SMARTAPI_TOTP_SECRET')
TELE_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELE_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL') or 60)

REQUIRED = [API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET, TELE_TOKEN, TELE_CHAT_ID]

app = Flask(__name__)

# Symbol configurations
SYMBOLS_CONFIG = {
    'NIFTY': {
        'spot_token': '99926000',
        'exchange': 'NSE',
        'strike_gap': 50,
        'expiry_type': 'weekly',  # Weekly expiry - Thursday
        'strikes_count': 21  # ATM ± 10
    },
    'BANKNIFTY': {
        'spot_token': '99926009',
        'exchange': 'NSE',
        'strike_gap': 100,
        'expiry_type': 'weekly',  # Weekly expiry - Wednesday
        'strikes_count': 21
    },
    'MIDCPNIFTY': {
        'spot_token': '99926037',
        'exchange': 'NSE',
        'strike_gap': 25,
        'expiry_type': 'weekly',  # Weekly expiry - Monday
        'strikes_count': 21
    },
    'FINNIFTY': {
        'spot_token': '99926074',
        'exchange': 'NSE',
        'strike_gap': 50,
        'expiry_type': 'weekly',  # Weekly expiry - Tuesday
        'strikes_count': 21
    },
    'SENSEX': {
        'spot_token': '99919000',
        'exchange': 'BSE',
        'strike_gap': 100,
        'expiry_type': 'weekly',  # Weekly expiry - Friday
        'strikes_count': 21
    },
    'HDFCBANK': {
        'spot_token': '1333',
        'exchange': 'NSE',
        'strike_gap': 20,
        'expiry_type': 'monthly',  # Monthly expiry - last Thursday
        'strikes_count': 21
    }
}

def tele_send_http(chat_id: str, text: str):
    """Send message using Telegram Bot HTTP API via requests (synchronous)."""
    try:
        token = TELE_TOKEN
        if not token:
            logger.error('TELEGRAM_BOT_TOKEN not set, cannot send Telegram message.')
            return False
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML"
        }
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code != 200:
            logger.warning('Telegram API returned %s: %s', r.status_code, r.text)
            return False
        return True
    except Exception as e:
        logger.exception('Failed to send Telegram message: %s', e)
        return False

def login_and_setup(api_key, client_id, password, totp_secret):
    if SmartConnect is None:
        raise RuntimeError('SmartAPI SDK not available. Check requirements.txt installation.')
    smartApi = SmartConnect(api_key=api_key)
    totp = pyotp.TOTP(totp_secret).now()
    logger.info('Logging in to SmartAPI...')
    data = smartApi.generateSession(client_id, password, totp)
    if not data or data.get('status') is False:
        raise RuntimeError(f"Login failed: {data}")
    authToken = data['data']['jwtToken']
    refreshToken = data['data']['refreshToken']
    logger.info(f"✅ Login successful! Auth token: {authToken[:20]}...")
    try:
        feedToken = smartApi.getfeedToken()
        logger.info(f"Feed token: {feedToken}")
    except Exception as e:
        logger.warning(f"Feed token failed: {e}")
        feedToken = None
    try:
        smartApi.generateToken(refreshToken)
    except Exception:
        pass
    return smartApi, authToken, refreshToken, feedToken

def get_next_expiry(expiry_type, symbol_name=''):
    """Get next expiry based on type and symbol"""
    today = datetime.now()
    
    if expiry_type == 'weekly':
        # Different weekly expiries for different indices
        if 'NIFTY' in symbol_name and 'BANK' not in symbol_name and 'FIN' not in symbol_name and 'MIDCP' not in symbol_name:
            # NIFTY - Thursday (weekday 3)
            target_day = 3
        elif 'BANKNIFTY' in symbol_name:
            # BANKNIFTY - Wednesday (weekday 2)
            target_day = 2
        elif 'FINNIFTY' in symbol_name:
            # FINNIFTY - Tuesday (weekday 1)
            target_day = 1
        elif 'MIDCPNIFTY' in symbol_name:
            # MIDCPNIFTY - Monday (weekday 0)
            target_day = 0
        elif 'SENSEX' in symbol_name:
            # SENSEX - Friday (weekday 4)
            target_day = 4
        else:
            # Default to Thursday
            target_day = 3
        
        days_ahead = target_day - today.weekday()
        if days_ahead <= 0:  # If today is target day or later, get next week
            days_ahead += 7
        expiry = today + timedelta(days=days_ahead)
        
    else:  # monthly
        # Get last Thursday of current month
        if today.month == 12:
            next_month = datetime(today.year + 1, 1, 1)
        else:
            next_month = datetime(today.year, today.month + 1, 1)
        
        last_day = next_month - timedelta(days=1)
        
        # Find last Thursday (weekday 3)
        while last_day.weekday() != 3:
            last_day = last_day - timedelta(days=1)
        
        expiry = last_day
    
    # Format: DDMMMYYYY (e.g., 30OCT2025)
    return expiry.strftime('%d%b%Y').upper()

def download_instruments(smartApi):
    """Download instrument master file from Angel One"""
    try:
        logger.info("📥 Downloading instruments master file...")
        url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            instruments = response.json()
            logger.info(f"✅ Downloaded {len(instruments)} instruments")
            return instruments
        else:
            logger.error(f"Failed to download instruments: {response.status_code}")
        return None
    except Exception as e:
        logger.exception(f"❌ Failed to download instruments: {e}")
        return None

def find_option_tokens(instruments, symbol, target_expiry, current_price, strike_gap, strikes_count):
    """Find option tokens for strikes around current price"""
    if not instruments:
        logger.error("No instruments available!")
        return []
    
    logger.info(f"🔍 Finding {strikes_count} strikes for {symbol}, Expiry: {target_expiry}, Price: {current_price}")
    
    # Calculate ATM and surrounding strikes
    atm = round(current_price / strike_gap) * strike_gap
    strikes = []
    
    # Get strikes above and below ATM
    half_strikes = strikes_count // 2
    for i in range(-half_strikes, half_strikes + 1):
        strikes.append(atm + (i * strike_gap))
    
    logger.info(f"🎯 ATM: {atm}, Strike gap: {strike_gap}, Range: {min(strikes)} to {max(strikes)}")
    
    option_tokens = []
    matched_strikes = set()
    
    for instrument in instruments:
        inst_name = instrument.get('name', '')
        inst_expiry = instrument.get('expiry', '')
        
        # Match instrument name and expiry
        if inst_name == symbol and inst_expiry == target_expiry:
            strike_raw = instrument.get('strike', '0')
            try:
                # Strike is in paise (as string), convert to rupees
                strike = float(strike_raw) / 100
            except (ValueError, TypeError):
                continue
                
            if strike > 0 and strike in strikes:
                matched_strikes.add(strike)
                symbol_name = instrument.get('symbol', '')
                option_type = 'CE' if 'CE' in symbol_name else 'PE'
                token = instrument.get('token')
                option_tokens.append({
                    'strike': strike,
                    'type': option_type,
                    'token': token,
                    'symbol': symbol_name,
                    'expiry': inst_expiry
                })
    
    logger.info(f"✅ Found {len(option_tokens)} option contracts for {symbol}")
    
    return sorted(option_tokens, key=lambda x: (x['strike'], x['type']))

def get_option_chain_data_full(smartApi, option_tokens):
    """Fetch full option chain data including Greeks, OI, Volume"""
    try:
        if not option_tokens:
            logger.warning("No option tokens provided")
            return {}
        
        logger.info(f"📡 Fetching FULL data for {len(option_tokens)} options...")
        
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-UserType': 'USER',
            'X-SourceID': 'WEB',
            'X-ClientLocalIP': '127.0.0.1',
            'X-ClientPublicIP': '127.0.0.1',
            'X-MACAddress': '00:00:00:00:00:00',
            'X-PrivateKey': API_KEY
        }
        
        all_tokens = [opt['token'] for opt in option_tokens]
        
        # Use FULL mode instead of LTP for complete data
        payload = {
            "mode": "FULL",
            "exchangeTokens": {
                "NFO": all_tokens
            }
        }
        
        response = requests.post(
            'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
            json=payload,
            headers=headers,
            timeout=20
        )
        
        logger.info(f"API Response Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('status'):
                result = {}
                fetched = data.get('data', {}).get('fetched', [])
                logger.info(f"✅ Fetched full data for {len(fetched)} instruments")
                
                for item in fetched:
                    token = item.get('symbolToken', '')
                    
                    # Extract all relevant fields
                    result[token] = {
                        'ltp': float(item.get('ltp', 0)),
                        'oi': int(item.get('oi', 0)),
                        'volume': int(item.get('volume', 0)),
                        'change_oi': int(item.get('oiDayHigh', 0)) - int(item.get('oiDayLow', 0)),  # Approximate
                        'iv': float(item.get('iv', 0)) if item.get('iv') else 0,
                        'delta': float(item.get('delta', 0)) if item.get('delta') else 0,
                        'theta': float(item.get('theta', 0)) if item.get('theta') else 0,
                        'gamma': float(item.get('gamma', 0)) if item.get('gamma') else 0,
                        'vega': float(item.get('vega', 0)) if item.get('vega') else 0,
                        'change': float(item.get('change', 0))
                    }
                
                if result:
                    logger.info(f"Sample data: {list(result.items())[0]}")
                return result
            else:
                logger.error(f"API returned status=false: {data}")
        else:
            logger.error(f"API error: {response.text}")
        
        return {}
        
    except Exception as e:
        logger.exception(f"❌ Failed to fetch option chain data: {e}")
        return {}

def get_spot_prices(smartApi):
    """Get spot prices for all symbols"""
    try:
        logger.info("📊 Fetching spot prices...")
        
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-UserType': 'USER',
            'X-SourceID': 'WEB',
            'X-ClientLocalIP': '127.0.0.1',
            'X-ClientPublicIP': '127.0.0.1',
            'X-MACAddress': '00:00:00:00:00:00',
            'X-PrivateKey': API_KEY
        }
        
        # Collect all spot tokens
        nse_tokens = []
        bse_tokens = []
        
        for symbol, config in SYMBOLS_CONFIG.items():
            token = config['spot_token']
            if config['exchange'] == 'NSE':
                nse_tokens.append(token)
            else:
                bse_tokens.append(token)
        
        payload = {
            "mode": "LTP",
            "exchangeTokens": {
                "NSE": nse_tokens,
                "BSE": bse_tokens
            }
        }
        
        response = requests.post(
            'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
            json=payload,
            headers=headers,
            timeout=10
        )
        
        logger.info(f"Spot API Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status'):
                result = {}
                fetched = data.get('data', {}).get('fetched', [])
                
                for item in fetched:
                    token = item.get('symbolToken', '')
                    ltp = float(item.get('ltp', 0))
                    
                    # Map token back to symbol name
                    for symbol, config in SYMBOLS_CONFIG.items():
                        if config['spot_token'] == token:
                            result[symbol] = ltp
                            logger.info(f"✅ {symbol}: ₹{ltp:,.2f}")
                            break
                
                return result
            else:
                logger.error(f"Spot API status=false: {data}")
        else:
            logger.error(f"Spot API error: {response.text}")
        
        return {}
        
    except Exception as e:
        logger.exception(f"❌ Failed to fetch spot prices: {e}")
        return {}

def format_option_chain_message(symbol, spot_price, expiry, option_data, full_data):
    """Format option chain data for Telegram - COMPACT version for 21 strikes"""
    messages = []
    messages.append(f"📊 <b>{symbol}</b>")
    messages.append(f"💰 ₹{spot_price:,.1f} | 📅 {expiry}\n")
    
    # Group by strike
    strikes = {}
    for opt in option_data:
        strike = opt['strike']
        if strike not in strikes:
            strikes[strike] = {'CE': {}, 'PE': {}}
        
        token = opt['token']
        data = full_data.get(token, {})
        strikes[strike][opt['type']] = data
    
    # Ultra compact header for 21 strikes
    messages.append("<code>CALL        |STRIKE| PUT</code>")
    messages.append("<code>LTP OI  Δ   |      |LTP OI  Δ</code>")
    messages.append("─" * 38)
    
    total_ce_oi = 0
    total_pe_oi = 0
    
    for strike in sorted(strikes.keys()):
        ce_data = strikes[strike].get('CE', {})
        pe_data = strikes[strike].get('PE', {})
        
        ce_ltp = ce_data.get('ltp', 0)
        ce_oi = ce_data.get('oi', 0)
        ce_chg_oi = ce_data.get('change_oi', 0)
        
        pe_ltp = pe_data.get('ltp', 0)
        pe_oi = pe_data.get('oi', 0)
        pe_chg_oi = pe_data.get('change_oi', 0)
        
        total_ce_oi += ce_oi
        total_pe_oi += pe_oi
        
        # Ultra compact formatting
        ce_oi_str = f"{ce_oi//1000}k" if ce_oi >= 1000 else f"{ce_oi}"
        pe_oi_str = f"{pe_oi//1000}k" if pe_oi >= 1000 else f"{pe_oi}"
        
        ce_chg_str = f"+{ce_chg_oi//1000}k" if ce_chg_oi > 1000 else (f"{ce_chg_oi//1000}k" if ce_chg_oi < -1000 else "")
        pe_chg_str = f"+{pe_chg_oi//1000}k" if pe_chg_oi > 1000 else (f"{pe_chg_oi//1000}k" if pe_chg_oi < -1000 else "")
        
        ce_str = f"{ce_ltp:>3.0f} {ce_oi_str:>3s} {ce_chg_str:>3s}" if ce_ltp > 0 else "            "
        pe_str = f"{pe_ltp:>3.0f} {pe_oi_str:>3s} {pe_chg_str:>3s}" if pe_ltp > 0 else "            "
        
        strike_str = f"{int(strike)}"
        
        messages.append(f"<code>{ce_str}|{strike_str:>6}|{pe_str}</code>")
    
    messages.append("─" * 38)
    
    # Summary
    if total_ce_oi > 0 or total_pe_oi > 0:
        pcr = total_pe_oi / total_ce_oi if total_ce_oi > 0 else 0
        messages.append(f"<b>PCR:</b> {pcr:.2f} | CE: {total_ce_oi//1000}k PE: {total_pe_oi//1000}k")
    
    messages.append(f"🕐 {time.strftime('%H:%M:%S')}")
    
    return "\n".join(messages)

def bot_loop():
    if not all(REQUIRED):
        logger.error('❌ Missing required environment variables. Bot will not start.')
        return

    try:
        smartApi, authToken, refreshToken, feedToken = login_and_setup(API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET)
        logger.info("✅ Login successful!")
    except Exception as e:
        logger.exception('❌ Login/setup failed: %s', e)
        tele_send_http(TELE_CHAT_ID, f'❌ Login failed: {e}')
        return

    symbols_list = ', '.join(SYMBOLS_CONFIG.keys())
    tele_send_http(TELE_CHAT_ID, f"✅ Enhanced Option Chain Bot Started!\n📊 Tracking: {symbols_list}\n⏱ Update: {POLL_INTERVAL}s")
    
    # Download instruments once
    logger.info("📥 Downloading instruments...")
    instruments = download_instruments(smartApi)
    if not instruments:
        error_msg = "❌ Failed to download instruments. Bot cannot continue."
        logger.error(error_msg)
        tele_send_http(TELE_CHAT_ID, error_msg)
        return
    
    # Calculate expiries for all symbols
    expiries = {}
    for symbol, config in SYMBOLS_CONFIG.items():
        expiry = get_next_expiry(config['expiry_type'], symbol)
        
        # Verify expiry exists in instruments
        available = sorted([i.get('expiry') for i in instruments 
                          if i.get('name') == symbol and i.get('expiry')])
        
        if expiry not in available and available:
            expiry = available[0]
            logger.info(f"📅 Using nearest {symbol} expiry: {expiry}")
        
        expiries[symbol] = expiry
        logger.info(f"📅 {symbol}: {expiry}")
    
    iteration = 0
    while True:
        try:
            iteration += 1
            logger.info(f"\n{'='*50}")
            logger.info(f"🔄 Iteration #{iteration} - {time.strftime('%H:%M:%S')}")
            logger.info(f"{'='*50}")
            
            # Get spot prices for all symbols
            spot_prices = get_spot_prices(smartApi)
            
            # Process each symbol
            for symbol, config in SYMBOLS_CONFIG.items():
                if symbol not in spot_prices:
                    logger.warning(f"⚠️ No spot price for {symbol}")
                    continue
                
                logger.info(f"\n--- Processing {symbol} ---")
                spot_price = spot_prices[symbol]
                expiry = expiries[symbol]
                
                # Find option tokens
                option_tokens = find_option_tokens(
                    instruments, 
                    symbol, 
                    expiry, 
                    spot_price,
                    config['strike_gap'],
                    config['strikes_count']
                )
                
                if option_tokens:
                    # Fetch full data
                    full_data = get_option_chain_data_full(smartApi, option_tokens)
                    if full_data:
                        msg = format_option_chain_message(symbol, spot_price, expiry, option_tokens, full_data)
                        tele_send_http(TELE_CHAT_ID, msg)
                        logger.info(f"✅ {symbol} data sent to Telegram")
                        time.sleep(2)  # Delay between messages
                    else:
                        logger.warning(f"⚠️ No data received for {symbol} options")
                else:
                    logger.warning(f"⚠️ No option contracts found for {symbol}")
            
            logger.info(f"✅ Iteration #{iteration} complete. Sleeping {POLL_INTERVAL}s...")
            
        except Exception as e:
            logger.exception(f"❌ Error in bot loop iteration #{iteration}: {e}")
            tele_send_http(TELE_CHAT_ID, f"⚠️ Error #{iteration}: {str(e)[:100]}")
        
        time.sleep(POLL_INTERVAL)

# Start bot in a background thread
thread = threading.Thread(target=bot_loop, daemon=True)
thread.start()

@app.route('/')
def index():
    status = {
        'bot_thread_alive': thread.is_alive(),
        'poll_interval': POLL_INTERVAL,
        'symbols': list(SYMBOLS_CONFIG.keys()),
        'smartapi_sdk_available': SmartConnect is not None,
        'service': 'Angel One Enhanced Option Chain Bot',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    return jsonify(status)

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'thread_alive': thread.is_alive()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)))
