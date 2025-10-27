import os
import time
import threading
import logging
from flask import Flask, jsonify
import pyotp
import requests
from datetime import datetime, timedelta
from collections import defaultdict

# ---- SmartAPI import ----
SmartConnect = None
try:
    from SmartApi import SmartConnect as _SC
    SmartConnect = _SC
    logging.info("SmartConnect imported successfully!")
except Exception as e:
    logging.error(f"Failed to import SmartConnect: {e}")
    SmartConnect = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
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

# Symbol configurations - CORRECTED based on NSE circular Oct 2024
SYMBOLS_CONFIG = {
    'NIFTY': {
        'spot_token': '99926000',
        'exchange': 'NSE',
        'strike_gap': 50,
        'expiry_type': 'weekly',  # Weekly still available
        'strikes_count': 21,
        'lot_size': 25
    },
    'BANKNIFTY': {
        'spot_token': '99926009',
        'exchange': 'NSE',
        'strike_gap': 100,
        'expiry_type': 'monthly',  # Weekly discontinued Oct 2024
        'strikes_count': 21,
        'lot_size': 15
    },
    'MIDCPNIFTY': {
        'spot_token': '99926037',
        'exchange': 'NSE',
        'strike_gap': 25,
        'expiry_type': 'monthly',  # Weekly discontinued Oct 2024
        'strikes_count': 21,
        'lot_size': 75
    },
    'FINNIFTY': {
        'spot_token': '99926074',
        'exchange': 'NSE',
        'strike_gap': 50,
        'expiry_type': 'monthly',  # Weekly discontinued Oct 2024
        'strikes_count': 21,
        'lot_size': 25
    },
    'SENSEX': {
        'spot_token': '99919000',
        'exchange': 'BSE',
        'strike_gap': 100,
        'expiry_type': 'weekly',  # BSE weekly still available
        'strikes_count': 21,
        'lot_size': 10
    },
    'HDFCBANK': {
        'spot_token': '1333',
        'exchange': 'NSE',
        'strike_gap': 20,
        'expiry_type': 'monthly',
        'strikes_count': 21,
        'lot_size': 550
    }
}

# Store previous OI data for change calculation
previous_oi = defaultdict(dict)

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
    logger.info(f"✅ Login successful!")
    try:
        feedToken = smartApi.getfeedToken()
        logger.info(f"Feed token obtained")
    except Exception as e:
        logger.warning(f"Feed token failed: {e}")
        feedToken = None
    try:
        smartApi.generateToken(refreshToken)
    except Exception:
        pass
    return smartApi, authToken, refreshToken, feedToken

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

def find_nearest_expiry(instruments, symbol):
    """Find the nearest available expiry from instruments for a symbol"""
    try:
        # Get all unique expiries for this symbol
        expiries = set()
        for inst in instruments:
            if inst.get('name') == symbol and inst.get('expiry'):
                exp = inst.get('expiry')
                if exp:
                    expiries.add(exp)
        
        if not expiries:
            logger.warning(f"No expiries found for {symbol}")
            return None
        
        # Parse expiries and find nearest future one
        today = datetime.now()
        future_expiries = []
        
        for exp_str in expiries:
            try:
                # Try different formats
                for fmt in ['%d%b%Y', '%d%b%y']:
                    try:
                        exp_date = datetime.strptime(exp_str, fmt)
                        if exp_date >= today:
                            future_expiries.append((exp_date, exp_str))
                        break
                    except:
                        continue
            except:
                continue
        
        if not future_expiries:
            logger.warning(f"No future expiries found for {symbol}")
            return None
        
        # Return the nearest one
        future_expiries.sort()
        nearest_expiry = future_expiries[0][1]
        logger.info(f"📅 {symbol} nearest expiry: {nearest_expiry}")
        return nearest_expiry
        
    except Exception as e:
        logger.exception(f"Error finding expiry for {symbol}: {e}")
        return None

def find_option_tokens(instruments, symbol, target_expiry, current_price, strike_gap, strikes_count):
    """Find option tokens for strikes around current price"""
    if not instruments or not target_expiry:
        logger.error(f"Missing instruments or expiry for {symbol}")
        return []
    
    logger.info(f"🔍 Finding {strikes_count} strikes for {symbol}, Expiry: {target_expiry}, Price: {current_price}")
    
    # Calculate ATM and surrounding strikes
    atm = round(current_price / strike_gap) * strike_gap
    strikes = []
    
    # Get strikes above and below ATM
    half_strikes = strikes_count // 2
    for i in range(-half_strikes, half_strikes + 1):
        strikes.append(atm + (i * strike_gap))
    
    logger.info(f"🎯 ATM: {atm}, Range: {min(strikes)} to {max(strikes)}")
    
    option_tokens = []
    
    for instrument in instruments:
        inst_name = instrument.get('name', '')
        inst_expiry = instrument.get('expiry', '')
        
        # Match instrument name and expiry
        if inst_name == symbol and inst_expiry == target_expiry:
            strike_raw = instrument.get('strike', '0')
            try:
                # Strike is in paise, convert to rupees
                strike = float(strike_raw) / 100
            except (ValueError, TypeError):
                continue
                
            if strike > 0 and strike in strikes:
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
    
    logger.info(f"✅ Found {len(option_tokens)} options for {symbol}")
    return sorted(option_tokens, key=lambda x: (x['strike'], x['type']))

def get_option_ltp_oi_volume(smartApi, option_tokens):
    """Fetch LTP, OI, Volume for options using Market Data API"""
    try:
        if not option_tokens:
            return {}
        
        logger.info(f"📡 Fetching market data for {len(option_tokens)} options...")
        
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
        
        # Split into batches of 50 tokens (API limit)
        all_tokens = [opt['token'] for opt in option_tokens]
        result = {}
        
        for i in range(0, len(all_tokens), 50):
            batch = all_tokens[i:i+50]
            
            payload = {
                "mode": "FULL",
                "exchangeTokens": {
                    "NFO": batch
                }
            }
            
            response = requests.post(
                'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
                json=payload,
                headers=headers,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status'):
                    fetched = data.get('data', {}).get('fetched', [])
                    
                    for item in fetched:
                        token = item.get('symbolToken', '')
                        result[token] = {
                            'ltp': float(item.get('ltp', 0)),
                            'oi': int(item.get('opnInterest', 0)),
                            'volume': int(item.get('tradeVolume', 0)),
                        }
            
            time.sleep(0.3)  # Rate limiting
        
        logger.info(f"✅ Fetched data for {len(result)} options")
        return result
        
    except Exception as e:
        logger.exception(f"❌ Failed to fetch market data: {e}")
        return {}

def get_option_greeks(smartApi, symbol, expiry):
    """Fetch Option Greeks using Option Greeks API - with error handling"""
    try:
        logger.info(f"🔢 Fetching Greeks for {symbol} {expiry}...")
        
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
        
        payload = {
            "name": symbol,
            "expirydate": expiry
        }
        
        response = requests.post(
            'https://apiconnect.angelbroking.com/rest/secure/angelbroking/marketData/v1/optionGreek',
            json=payload,
            headers=headers,
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status'):
                greeks_data = {}
                for item in data.get('data', []):
                    strike = float(item.get('strikePrice', 0))
                    opt_type = item.get('optionType', '')
                    
                    key = f"{strike}_{opt_type}"
                    greeks_data[key] = {
                        'delta': float(item.get('delta', 0)),
                        'gamma': float(item.get('gamma', 0)),
                        'theta': float(item.get('theta', 0)),
                        'vega': float(item.get('vega', 0)),
                        'iv': float(item.get('impliedVolatility', 0))
                    }
                
                logger.info(f"✅ Got Greeks for {len(greeks_data)} options")
                return greeks_data
            else:
                # Don't log error for "No Data Available" - it's expected after market hours
                msg = data.get('message', '')
                if 'No Data Available' not in msg:
                    logger.warning(f"Greeks API: {msg}")
        elif response.status_code == 403:
            logger.debug(f"Greeks API rate limited (403) - skipping")
        else:
            logger.debug(f"Greeks API HTTP {response.status_code}")
        
        return {}
        
    except Exception as e:
        logger.debug(f"Greeks fetch skipped: {e}")
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
        
        return {}
        
    except Exception as e:
        logger.exception(f"❌ Failed to fetch spot prices: {e}")
        return {}

def format_volume(vol):
    """Format volume in readable format"""
    if vol >= 10000000:  # 1 Crore
        return f"{vol/10000000:.1f}Cr"
    elif vol >= 100000:  # 1 Lakh
        return f"{vol/100000:.1f}L"
    elif vol >= 1000:
        return f"{vol/1000:.0f}k"
    return str(vol)

def format_option_chain_message(symbol, spot_price, expiry, option_data, market_data, greeks_data, lot_size):
    """Format compact option chain message with all data"""
    messages = []
    messages.append(f"📊 <b>{symbol}</b>")
    messages.append(f"💰 ₹{spot_price:,.1f} | 📅 {expiry} | Lot: {lot_size}\n")
    
    # Group by strike
    strikes = {}
    for opt in option_data:
        strike = opt['strike']
        if strike not in strikes:
            strikes[strike] = {'CE': {}, 'PE': {}}
        
        token = opt['token']
        mdata = market_data.get(token, {})
        
        # Get Greeks
        greek_key = f"{strike}_{opt['type']}"
        gdata = greeks_data.get(greek_key, {})
        
        # Calculate OI change
        prev_oi = previous_oi.get(symbol, {}).get(token, 0)
        current_oi = mdata.get('oi', 0)
        oi_change = current_oi - prev_oi
        
        # Store current OI for next iteration
        if symbol not in previous_oi:
            previous_oi[symbol] = {}
        previous_oi[symbol][token] = current_oi
        
        strikes[strike][opt['type']] = {
            **mdata,
            **gdata,
            'oi_change': oi_change
        }
    
    # Compact header
    messages.append("<code>CE           |STRIKE|PE</code>")
    messages.append("<code>LTP OI  Vol  |      |LTP OI  Vol</code>")
    messages.append("─" * 40)
    
    total_ce_oi = 0
    total_pe_oi = 0
    total_ce_vol = 0
    total_pe_vol = 0
    
    for strike in sorted(strikes.keys()):
        ce = strikes[strike].get('CE', {})
        pe = strikes[strike].get('PE', {})
        
        ce_ltp = ce.get('ltp', 0)
        ce_oi = ce.get('oi', 0)
        ce_vol = ce.get('volume', 0)
        
        pe_ltp = pe.get('ltp', 0)
        pe_oi = pe.get('oi', 0)
        pe_vol = pe.get('volume', 0)
        
        total_ce_oi += ce_oi
        total_pe_oi += pe_oi
        total_ce_vol += ce_vol
        total_pe_vol += pe_vol
        
        # Format compact
        def fmt_oi(n):
            if n >= 1000000:
                return f"{n//1000}k"
            elif n >= 1000:
                return f"{n//1000}k"
            return str(int(n)) if n > 0 else "-"
        
        ce_oi_str = fmt_oi(ce_oi)
        pe_oi_str = fmt_oi(pe_oi)
        
        ce_vol_str = format_volume(ce_vol) if ce_vol > 0 else "-"
        pe_vol_str = format_volume(pe_vol) if pe_vol > 0 else "-"
        
        ce_str = f"{ce_ltp:>3.0f} {ce_oi_str:>4} {ce_vol_str:>4}" if ce_ltp > 0 else "              "
        pe_str = f"{pe_ltp:>3.0f} {pe_oi_str:>4} {pe_vol_str:>4}" if pe_ltp > 0 else "              "
        
        messages.append(f"<code>{ce_str}|{int(strike):>6}|{pe_str}</code>")
    
    messages.append("─" * 40)
    
    # Summary
    if total_ce_oi > 0 or total_pe_oi > 0:
        pcr = total_pe_oi / total_ce_oi if total_ce_oi > 0 else 0
        messages.append(f"<b>PCR:</b> {pcr:.2f}")
        messages.append(f"<b>OI:</b> CE {format_volume(total_ce_oi)} | PE {format_volume(total_pe_oi)}")
    
    if total_ce_vol > 0 or total_pe_vol > 0:
        messages.append(f"<b>Vol:</b> CE {format_volume(total_ce_vol)} | PE {format_volume(total_pe_vol)}")
    
    messages.append(f"\n🕐 {time.strftime('%H:%M:%S')}")
    
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
    tele_send_http(TELE_CHAT_ID, f"✅ Enhanced Option Chain Bot Started!\n📊 Tracking: {symbols_list}\n⏱ Update: {POLL_INTERVAL}s\n\n⏳ Downloading instruments...")
    
    # Download instruments
    instruments = download_instruments(smartApi)
    if not instruments:
        error_msg = "❌ Failed to download instruments. Bot cannot continue."
        logger.error(error_msg)
        tele_send_http(TELE_CHAT_ID, error_msg)
        return
    
    # Find nearest expiries for all symbols
    expiries = {}
    for symbol in SYMBOLS_CONFIG.keys():
        expiry = find_nearest_expiry(instruments, symbol)
        if expiry:
            expiries[symbol] = expiry
        else:
            logger.error(f"❌ Could not find expiry for {symbol}")
    
    expiry_msg = "\n".join([f"📅 {sym}: {exp}" for sym, exp in expiries.items()])
    tele_send_http(TELE_CHAT_ID, f"📅 <b>Expiries Found:</b>\n{expiry_msg}\n\n🔄 Starting data fetch...")
    
    iteration = 0
    while True:
        try:
            iteration += 1
            logger.info(f"\n{'='*50}")
            logger.info(f"🔄 Iteration #{iteration} - {time.strftime('%H:%M:%S')}")
            logger.info(f"{'='*50}")
            
            # Get spot prices
            spot_prices = get_spot_prices(smartApi)
            
            # Process each symbol
            for symbol, config in SYMBOLS_CONFIG.items():
                if symbol not in expiries:
                    logger.warning(f"⚠️ No expiry for {symbol}, skipping")
                    continue
                
                if symbol not in spot_prices:
                    logger.warning(f"⚠️ No spot price for {symbol}, skipping")
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
                
                if not option_tokens:
                    logger.warning(f"⚠️ No options found for {symbol}")
                    continue
                
                # Fetch market data (LTP, OI, Volume)
                market_data = get_option_ltp_oi_volume(smartApi, option_tokens)
                
                # Try to fetch Greeks (may fail after market hours or due to rate limiting)
                greeks_data = {}
                if iteration % 3 == 1:  # Only try Greeks every 3rd iteration to avoid rate limits
                    greeks_data = get_option_greeks(smartApi, symbol, expiry)
                
                if market_data:
                    msg = format_option_chain_message(
                        symbol, spot_price, expiry, 
                        option_tokens, market_data, greeks_data,
                        config['lot_size']
                    )
                    tele_send_http(TELE_CHAT_ID, msg)
                    logger.info(f"✅ {symbol} data sent")
                    time.sleep(2)
                else:
                    logger.warning(f"⚠️ No market data for {symbol}")
            
            logger.info(f"✅ Iteration #{iteration} complete. Sleeping {POLL_INTERVAL}s...")
            
        except Exception as e:
            logger.exception(f"❌ Error in iteration #{iteration}: {e}")
            tele_send_http(TELE_CHAT_ID, f"⚠️ Error #{iteration}: {str(e)[:100]}")
        
        time.sleep(POLL_INTERVAL)

# Start bot in background thread
thread = threading.Thread(target=bot_loop, daemon=True)
thread.start()

@app.route('/')
def index():
    status = {
        'bot_thread_alive': thread.is_alive(),
        'poll_interval': POLL_INTERVAL,
        'symbols': list(SYMBOLS_CONFIG.keys()),
        'smartapi_sdk_available': SmartConnect is not None,
        'service': 'Angel One Enhanced Option Chain Bot v3',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'note': 'BANKNIFTY, FINNIFTY, MIDCPNIFTY weekly expiry discontinued Oct 2024'
    }
    return jsonify(status)

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'thread_alive': thread.is_alive()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)))
