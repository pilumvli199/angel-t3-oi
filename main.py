import os
import time
import threading
import logging
from flask import Flask, jsonify
import pyotp
import requests
from datetime import datetime, timedelta
from collections import defaultdict
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import io

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
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL') or 300)  # 5 min default for charts

REQUIRED = [API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET, TELE_TOKEN, TELE_CHAT_ID]

app = Flask(__name__)

# Symbol configurations - CORRECTED
SYMBOLS_CONFIG = {
    'NIFTY': {
        'spot_token': '99926000',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 50,
        'strikes_count': 21,
        'lot_size': 25,
        'name_in_instruments': 'NIFTY'  # Exact match
    },
    'BANKNIFTY': {
        'spot_token': '99926009',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 100,
        'strikes_count': 21,
        'lot_size': 15,
        'name_in_instruments': 'BANKNIFTY'
    },
    'MIDCPNIFTY': {
        'spot_token': '99926037',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 25,
        'strikes_count': 21,
        'lot_size': 75,
        'name_in_instruments': 'MIDCPNIFTY'  # Check instruments file
    },
    'FINNIFTY': {
        'spot_token': '99926074',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 50,
        'strikes_count': 21,
        'lot_size': 25,
        'name_in_instruments': 'FINNIFTY'
    },
    'SENSEX': {
        'spot_token': '99919000',
        'exchange': 'BSE',
        'exch_seg': 'BFO',
        'strike_gap': 100,
        'strikes_count': 21,
        'lot_size': 10,
        'name_in_instruments': 'SENSEX'
    },
    'HDFCBANK': {
        'spot_token': '1333',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 20,
        'strikes_count': 21,
        'lot_size': 550,
        'name_in_instruments': 'HDFCBANK'
    }
}

# Store previous OI data
previous_oi = defaultdict(dict)

def tele_send_http(chat_id: str, text: str):
    """Send text message to Telegram"""
    try:
        token = TELE_TOKEN
        if not token:
            logger.error('TELEGRAM_BOT_TOKEN not set')
            return False
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        r = requests.post(url, json=payload, timeout=10)
        return r.status_code == 200
    except Exception as e:
        logger.exception(f'Failed to send message: {e}')
        return False

def tele_send_photo(chat_id: str, photo_bytes: bytes, caption: str = ""):
    """Send photo to Telegram"""
    try:
        token = TELE_TOKEN
        if not token:
            logger.error('TELEGRAM_BOT_TOKEN not set')
            return False
        url = f"https://api.telegram.org/bot{token}/sendPhoto"
        files = {'photo': ('chart.png', photo_bytes, 'image/png')}
        data = {'chat_id': chat_id, 'caption': caption, 'parse_mode': 'HTML'}
        r = requests.post(url, files=files, data=data, timeout=30)
        return r.status_code == 200
    except Exception as e:
        logger.exception(f'Failed to send photo: {e}')
        return False

def login_and_setup(api_key, client_id, password, totp_secret):
    if SmartConnect is None:
        raise RuntimeError('SmartAPI SDK not available')
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
    except Exception as e:
        logger.warning(f"Feed token failed: {e}")
        feedToken = None
    try:
        smartApi.generateToken(refreshToken)
    except:
        pass
    return smartApi, authToken, refreshToken, feedToken

def download_instruments(smartApi):
    """Download instrument master file"""
    try:
        logger.info("📥 Downloading instruments...")
        url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            instruments = response.json()
            logger.info(f"✅ Downloaded {len(instruments)} instruments")
            
            # Debug: Check what names exist for each symbol
            for symbol, config in SYMBOLS_CONFIG.items():
                # Try exact match
                exact = [i for i in instruments if i.get('name') == config['name_in_instruments'] and i.get('exch_seg') == config['exch_seg']]
                logger.info(f"   {symbol}: {len(exact)} contracts with name '{config['name_in_instruments']}'")
                
                # If no exact match, try partial
                if len(exact) == 0:
                    partial = [i for i in instruments if symbol in i.get('name', '') and i.get('exch_seg') == config['exch_seg']]
                    if partial:
                        sample_name = partial[0].get('name')
                        logger.info(f"   Found partial matches with name: '{sample_name}'")
                        # Update config
                        config['name_in_instruments'] = sample_name
            
            return instruments
        else:
            logger.error(f"Failed to download instruments: {response.status_code}")
        return None
    except Exception as e:
        logger.exception(f"❌ Failed to download instruments: {e}")
        return None

def find_nearest_expiry(instruments, symbol, exch_seg, name_in_inst):
    """Find nearest available expiry"""
    try:
        expiries = set()
        for inst in instruments:
            if inst.get('name') == name_in_inst and inst.get('exch_seg') == exch_seg and inst.get('expiry'):
                expiries.add(inst.get('expiry'))
        
        if not expiries:
            logger.warning(f"No expiries for {symbol}")
            return None
        
        today = datetime.now()
        future_expiries = []
        
        for exp_str in expiries:
            try:
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
            return None
        
        future_expiries.sort()
        nearest = future_expiries[0][1]
        logger.info(f"📅 {symbol}: {nearest}")
        return nearest
    except Exception as e:
        logger.exception(f"Error finding expiry: {e}")
        return None

def find_option_tokens(instruments, symbol, target_expiry, current_price, strike_gap, strikes_count, exch_seg, name_in_inst):
    """Find option tokens"""
    if not instruments or not target_expiry:
        return []
    
    atm = round(current_price / strike_gap) * strike_gap
    strikes = []
    half = strikes_count // 2
    for i in range(-half, half + 1):
        strikes.append(atm + (i * strike_gap))
    
    option_tokens = []
    for inst in instruments:
        if inst.get('name') == name_in_inst and inst.get('expiry') == target_expiry and inst.get('exch_seg') == exch_seg:
            try:
                strike = float(inst.get('strike', '0')) / 100
            except:
                continue
            
            if strike > 0 and strike in strikes:
                symbol_name = inst.get('symbol', '')
                option_type = 'CE' if 'CE' in symbol_name else 'PE'
                token = inst.get('token')
                option_tokens.append({
                    'strike': strike,
                    'type': option_type,
                    'token': token,
                    'symbol': symbol_name,
                    'expiry': target_expiry
                })
    
    logger.info(f"✅ {symbol}: {len(option_tokens)} options found")
    return sorted(option_tokens, key=lambda x: (x['strike'], x['type']))

def get_option_data(smartApi, option_tokens, exch_seg):
    """Fetch option market data"""
    try:
        if not option_tokens:
            return {}
        
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'X-PrivateKey': API_KEY
        }
        
        all_tokens = [opt['token'] for opt in option_tokens]
        result = {}
        
        for i in range(0, len(all_tokens), 50):
            batch = all_tokens[i:i+50]
            payload = {"mode": "FULL", "exchangeTokens": {exch_seg: batch}}
            
            response = requests.post(
                'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
                json=payload, headers=headers, timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status'):
                    for item in data.get('data', {}).get('fetched', []):
                        token = item.get('symbolToken', '')
                        result[token] = {
                            'ltp': float(item.get('ltp', 0)),
                            'oi': int(item.get('opnInterest', 0)),
                            'volume': int(item.get('tradeVolume', 0)),
                        }
            time.sleep(0.3)
        
        return result
    except Exception as e:
        logger.exception(f"Failed to fetch data: {e}")
        return {}

def get_spot_prices(smartApi):
    """Get spot prices"""
    try:
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'X-PrivateKey': API_KEY
        }
        
        nse_tokens = []
        bse_tokens = []
        
        for config in SYMBOLS_CONFIG.values():
            if config['exchange'] == 'NSE':
                nse_tokens.append(config['spot_token'])
            else:
                bse_tokens.append(config['spot_token'])
        
        payload = {"mode": "LTP", "exchangeTokens": {"NSE": nse_tokens, "BSE": bse_tokens}}
        
        response = requests.post(
            'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
            json=payload, headers=headers, timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status'):
                result = {}
                for item in data.get('data', {}).get('fetched', []):
                    token = item.get('symbolToken', '')
                    ltp = float(item.get('ltp', 0))
                    for symbol, config in SYMBOLS_CONFIG.items():
                        if config['spot_token'] == token:
                            result[symbol] = ltp
                            break
                return result
        return {}
    except Exception as e:
        logger.exception(f"Failed to fetch spots: {e}")
        return {}

def get_historical_candles(smartApi, symbol, token, exchange):
    """Fetch last 500 candles in 15-min timeframe"""
    try:
        logger.info(f"📊 Fetching candles for {symbol}...")
        
        # Calculate date range for 500 candles in 15-min
        # Market hours: 9:15 to 15:30 = 6.25 hours = 25 candles per day
        # 500 candles = ~20 trading days
        to_date = datetime.now()
        from_date = to_date - timedelta(days=30)  # Extra buffer
        
        params = {
            "exchange": exchange,
            "symboltoken": token,
            "interval": "FIFTEEN_MINUTE",
            "fromdate": from_date.strftime("%Y-%m-%d 09:15"),
            "todate": to_date.strftime("%Y-%m-%d %H:%M")
        }
        
        response = smartApi.getCandleData(params)
        
        if response and response.get('status'):
            candles = response.get('data', [])
            logger.info(f"✅ Got {len(candles)} candles for {symbol}")
            
            # Convert to DataFrame
            df = pd.DataFrame(candles, columns=['timestamp', 'open', 'high', 'low', 'close', 'volume'])
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Take last 500
            if len(df) > 500:
                df = df.tail(500)
            
            return df
        else:
            logger.warning(f"No candle data for {symbol}: {response}")
            return None
    except Exception as e:
        logger.exception(f"Failed to fetch candles: {e}")
        return None

def create_candlestick_chart(df, symbol, spot_price):
    """Create TradingView-style candlestick chart"""
    try:
        fig, ax = plt.subplots(figsize=(16, 9), facecolor='white')
        ax.set_facecolor('white')
        
        # Plot candlesticks
        for idx, row in df.iterrows():
            open_price = row['open']
            high_price = row['high']
            low_price = row['low']
            close_price = row['close']
            
            # Color: Green if close > open, Red otherwise
            color = '#26a69a' if close_price >= open_price else '#ef5350'
            
            # Draw high-low line
            ax.plot([idx, idx], [low_price, high_price], color=color, linewidth=1)
            
            # Draw candle body
            body_height = abs(close_price - open_price)
            body_bottom = min(open_price, close_price)
            rect = Rectangle((idx - 0.4, body_bottom), 0.8, body_height, 
                           facecolor=color, edgecolor=color, linewidth=0)
            ax.add_patch(rect)
        
        # Styling
        ax.set_xlabel('Time', fontsize=12, fontweight='bold')
        ax.set_ylabel('Price', fontsize=12, fontweight='bold')
        ax.set_title(f'{symbol} - 15 Min Candlestick Chart | Spot: ₹{spot_price:,.2f}', 
                    fontsize=16, fontweight='bold', pad=20)
        
        # Grid
        ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.5)
        ax.set_axisbelow(True)
        
        # X-axis labels (show every 50th candle)
        step = max(1, len(df) // 10)
        xticks = range(0, len(df), step)
        xticklabels = [df.iloc[i]['timestamp'].strftime('%d-%b %H:%M') for i in xticks]
        ax.set_xticks(xticks)
        ax.set_xticklabels(xticklabels, rotation=45, ha='right')
        
        plt.tight_layout()
        
        # Save to bytes
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100, facecolor='white')
        buf.seek(0)
        plt.close(fig)
        
        return buf.getvalue()
    except Exception as e:
        logger.exception(f"Failed to create chart: {e}")
        return None

def format_volume(vol):
    if vol >= 10000000:
        return f"{vol/10000000:.1f}Cr"
    elif vol >= 100000:
        return f"{vol/100000:.1f}L"
    elif vol >= 1000:
        return f"{vol/1000:.0f}k"
    return str(vol)

def format_option_chain(symbol, spot_price, expiry, option_data, market_data, lot_size):
    """Format option chain message"""
    msg = []
    msg.append(f"📊 <b>{symbol}</b>")
    msg.append(f"💰 ₹{spot_price:,.1f} | 📅 {expiry} | Lot: {lot_size}\n")
    
    strikes = {}
    for opt in option_data:
        strike = opt['strike']
        if strike not in strikes:
            strikes[strike] = {'CE': {}, 'PE': {}}
        
        token = opt['token']
        mdata = market_data.get(token, {})
        
        prev_oi = previous_oi.get(symbol, {}).get(token, 0)
        current_oi = mdata.get('oi', 0)
        oi_change = current_oi - prev_oi
        
        if symbol not in previous_oi:
            previous_oi[symbol] = {}
        previous_oi[symbol][token] = current_oi
        
        strikes[strike][opt['type']] = {**mdata, 'oi_change': oi_change}
    
    msg.append("<code>CE           |STRIKE|PE</code>")
    msg.append("<code>LTP OI  Vol  |      |LTP OI  Vol</code>")
    msg.append("─" * 40)
    
    total_ce_oi = 0
    total_pe_oi = 0
    
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
        
        ce_oi_str = f"{ce_oi//1000}k" if ce_oi >= 1000 else str(ce_oi) if ce_oi > 0 else "-"
        pe_oi_str = f"{pe_oi//1000}k" if pe_oi >= 1000 else str(pe_oi) if pe_oi > 0 else "-"
        
        ce_vol_str = format_volume(ce_vol) if ce_vol > 0 else "-"
        pe_vol_str = format_volume(pe_vol) if pe_vol > 0 else "-"
        
        ce_str = f"{ce_ltp:>3.0f} {ce_oi_str:>4} {ce_vol_str:>4}" if ce_ltp > 0 else "              "
        pe_str = f"{pe_ltp:>3.0f} {pe_oi_str:>4} {pe_vol_str:>4}" if pe_ltp > 0 else "              "
        
        msg.append(f"<code>{ce_str}|{int(strike):>6}|{pe_str}</code>")
    
    msg.append("─" * 40)
    
    if total_ce_oi > 0 or total_pe_oi > 0:
        pcr = total_pe_oi / total_ce_oi if total_ce_oi > 0 else 0
        msg.append(f"<b>PCR:</b> {pcr:.2f} | OI: CE {format_volume(total_ce_oi)} PE {format_volume(total_pe_oi)}")
    
    msg.append(f"🕐 {time.strftime('%H:%M:%S')}")
    
    return "\n".join(msg)

def bot_loop():
    if not all(REQUIRED):
        logger.error('❌ Missing env variables')
        return

    try:
        smartApi, *_ = login_and_setup(API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET)
    except Exception as e:
        logger.exception('❌ Login failed')
        tele_send_http(TELE_CHAT_ID, f'❌ Login failed: {e}')
        return

    tele_send_http(TELE_CHAT_ID, "✅ <b>Option Chain + Chart Bot Started!</b>\n⏱ Updates every 5 min\n\n⏳ Loading...")
    
    instruments = download_instruments(smartApi)
    if not instruments:
        logger.error("No instruments")
        return
    
    # Find expiries
    expiries = {}
    for symbol, config in SYMBOLS_CONFIG.items():
        exp = find_nearest_expiry(instruments, symbol, config['exch_seg'], config['name_in_instruments'])
        if exp:
            expiries[symbol] = exp
    
    iteration = 0
    while True:
        try:
            iteration += 1
            logger.info(f"\n{'='*50}\n🔄 Iteration #{iteration}\n{'='*50}")
            
            spot_prices = get_spot_prices(smartApi)
            
            for symbol, config in SYMBOLS_CONFIG.items():
                if symbol not in expiries or symbol not in spot_prices:
                    continue
                
                spot_price = spot_prices[symbol]
                expiry = expiries[symbol]
                
                # Option chain
                option_tokens = find_option_tokens(
                    instruments, symbol, expiry, spot_price,
                    config['strike_gap'], config['strikes_count'],
                    config['exch_seg'], config['name_in_instruments']
                )
                
                if option_tokens:
                    market_data = get_option_data(smartApi, option_tokens, config['exch_seg'])
                    if market_data:
                        msg = format_option_chain(symbol, spot_price, expiry, option_tokens, market_data, config['lot_size'])
                        tele_send_http(TELE_CHAT_ID, msg)
                        time.sleep(2)
                
                # Candlestick chart
                candle_df = get_historical_candles(smartApi, symbol, config['spot_token'], config['exchange'])
                if candle_df is not None and len(candle_df) > 0:
                    chart_bytes = create_candlestick_chart(candle_df, symbol, spot_price)
                    if chart_bytes:
                        tele_send_photo(TELE_CHAT_ID, chart_bytes, f"📊 {symbol} Candlestick Chart")
                        logger.info(f"✅ {symbol} chart sent")
                        time.sleep(2)
            
            logger.info(f"✅ Iteration #{iteration} done. Sleep {POLL_INTERVAL}s...")
            
        except Exception as e:
            logger.exception(f"❌ Error: {e}")
            tele_send_http(TELE_CHAT_ID, f"⚠️ Error: {str(e)[:100]}")
        
        time.sleep(POLL_INTERVAL)

# Start bot
thread = threading.Thread(target=bot_loop, daemon=True)
thread.start()

@app.route('/')
def index():
    return jsonify({
        'service': 'Angel One Option Chain + Chart Bot',
        'bot_alive': thread.is_alive(),
        'symbols': list(SYMBOLS_CONFIG.keys()),
        'features': ['Option Chain', 'Candlestick Charts', 'OI Tracking'],
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'thread': thread.is_alive()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)))
