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
matplotlib.use('Agg')
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
logger = logging.getLogger('angel-bot')

# Load config
API_KEY = os.getenv('SMARTAPI_API_KEY')
CLIENT_ID = os.getenv('SMARTAPI_CLIENT_ID')
PASSWORD = os.getenv('SMARTAPI_PASSWORD')
TOTP_SECRET = os.getenv('SMARTAPI_TOTP_SECRET')
TELE_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELE_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL') or 300)  # 5 min

REQUIRED = [API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET, TELE_TOKEN, TELE_CHAT_ID]

app = Flask(__name__)

# NIFTY 50 STOCKS with tokens (top 50 by market cap)
NIFTY50_STOCKS = {
    'RELIANCE': {'token': '2885', 'lot_size': 250},
    'TCS': {'token': '11536', 'lot_size': 300},
    'HDFCBANK': {'token': '1333', 'lot_size': 550},
    'INFY': {'token': '1594', 'lot_size': 300},
    'ICICIBANK': {'token': '4963', 'lot_size': 1375},
    'HINDUNILVR': {'token': '1394', 'lot_size': 300},
    'BHARTIARTL': {'token': '10604', 'lot_size': 1765},
    'ITC': {'token': '1660', 'lot_size': 1600},
    'SBIN': {'token': '3045', 'lot_size': 1500},
    'LT': {'token': '11483', 'lot_size': 300},
    'BAJFINANCE': {'token': '16675', 'lot_size': 125},
    'KOTAKBANK': {'token': '1922', 'lot_size': 400},
    'ASIANPAINT': {'token': '3718', 'lot_size': 300},
    'HCLTECH': {'token': '7229', 'lot_size': 700},
    'MARUTI': {'token': '10999', 'lot_size': 100},
    'AXISBANK': {'token': '5900', 'lot_size': 1200},
    'SUNPHARMA': {'token': '3351', 'lot_size': 700},
    'TITAN': {'token': '3506', 'lot_size': 300},
    'ULTRACEMCO': {'token': '11532', 'lot_size': 100},
    'ADANIENT': {'token': '25', 'lot_size': 250},
    'NESTLEIND': {'token': '17963', 'lot_size': 25},
    'BAJAJFINSV': {'token': '16669', 'lot_size': 125},
    'WIPRO': {'token': '3787', 'lot_size': 1200},
    'TATAMOTORS': {'token': '3456', 'lot_size': 1500},
    'POWERGRID': {'token': '14977', 'lot_size': 3000},
    'ONGC': {'token': '2475', 'lot_size': 3700},
    'NTPC': {'token': '11630', 'lot_size': 3000},
    'M&M': {'token': '10999', 'lot_size': 300},
    'TATASTEEL': {'token': '3499', 'lot_size': 2500},
    'JSWSTEEL': {'token': '11723', 'lot_size': 700},
    'TECHM': {'token': '13538', 'lot_size': 600},
    'DIVISLAB': {'token': '10940', 'lot_size': 200},
    'INDUSINDBK': {'token': '5258', 'lot_size': 900},
    'ADANIPORTS': {'token': '15083', 'lot_size': 1000},
    'DRREDDY': {'token': '881', 'lot_size': 125},
    'COALINDIA': {'token': '20374', 'lot_size': 3375},
    'BAJAJ-AUTO': {'token': '16669', 'lot_size': 125},
    'HINDALCO': {'token': '1363', 'lot_size': 3000},
    'BRITANNIA': {'token': '547', 'lot_size': 200},
    'EICHERMOT': {'token': '910', 'lot_size': 40},
    'CIPLA': {'token': '694', 'lot_size': 700},
    'BPCL': {'token': '526', 'lot_size': 1600},
    'GRASIM': {'token': '1232', 'lot_size': 375},
    'SBILIFE': {'token': '21808', 'lot_size': 500},
    'HDFCLIFE': {'token': '467', 'lot_size': 700},
    'APOLLOHOSP': {'token': '157', 'lot_size': 125},
    'HEROMOTOCO': {'token': '1348', 'lot_size': 100},
    'TATACONSUM': {'token': '3432', 'lot_size': 1000},
    'VEDL': {'token': '3063', 'lot_size': 2400},
    'UPL': {'token': '11287', 'lot_size': 1500}
}

# Index configurations
INDICES_CONFIG = {
    'NIFTY': {
        'spot_token': '99926000',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 50,
        'strikes_count': 31,  # Increased for full chain
        'lot_size': 25,
        'name_in_instruments': 'NIFTY'
    },
    'BANKNIFTY': {
        'spot_token': '99926009',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 100,
        'strikes_count': 31,
        'lot_size': 15,
        'name_in_instruments': 'BANKNIFTY'
    },
    'FINNIFTY': {
        'spot_token': '99926074',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 50,
        'strikes_count': 31,
        'lot_size': 25,
        'name_in_instruments': 'FINNIFTY'
    }
}

# Store previous data
previous_oi = defaultdict(dict)
previous_stock_prices = {}

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
    """Fetch option market data with volume"""
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
                            'change': float(item.get('change', 0)),
                            'bid': float(item.get('bid', 0)),
                            'ask': float(item.get('ask', 0)),
                        }
            time.sleep(0.3)
        
        return result
    except Exception as e:
        logger.exception(f"Failed to fetch option data: {e}")
        return {}

def get_stock_prices(smartApi):
    """Get Nifty 50 stock prices"""
    try:
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'X-PrivateKey': API_KEY
        }
        
        all_tokens = [info['token'] for info in NIFTY50_STOCKS.values()]
        result = {}
        
        # Batch process in groups of 50
        for i in range(0, len(all_tokens), 50):
            batch = all_tokens[i:i+50]
            payload = {"mode": "FULL", "exchangeTokens": {"NSE": batch}}
            
            response = requests.post(
                'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
                json=payload, headers=headers, timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status'):
                    for item in data.get('data', {}).get('fetched', []):
                        token = item.get('symbolToken', '')
                        ltp = float(item.get('ltp', 0))
                        change = float(item.get('change', 0))
                        pct_change = float(item.get('pChange', 0))
                        volume = int(item.get('tradeVolume', 0))
                        
                        for symbol, info in NIFTY50_STOCKS.items():
                            if info['token'] == token:
                                result[symbol] = {
                                    'ltp': ltp,
                                    'change': change,
                                    'pct_change': pct_change,
                                    'volume': volume
                                }
                                break
            time.sleep(0.3)
        
        return result
    except Exception as e:
        logger.exception(f"Failed to fetch stock prices: {e}")
        return {}

def get_index_prices(smartApi):
    """Get index spot prices"""
    try:
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'X-PrivateKey': API_KEY
        }
        
        nse_tokens = [config['spot_token'] for config in INDICES_CONFIG.values()]
        payload = {"mode": "LTP", "exchangeTokens": {"NSE": nse_tokens}}
        
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
                    for symbol, config in INDICES_CONFIG.items():
                        if config['spot_token'] == token:
                            result[symbol] = ltp
                            break
                return result
        return {}
    except Exception as e:
        logger.exception(f"Failed to fetch index prices: {e}")
        return {}

def get_historical_candles(smartApi, symbol, token, exchange):
    """Fetch last 500 candles in 15-min timeframe"""
    try:
        logger.info(f"📊 Fetching candles for {symbol}...")
        
        to_date = datetime.now()
        from_date = to_date - timedelta(days=30)
        
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
            
            df = pd.DataFrame(candles, columns=['timestamp', 'open', 'high', 'low', 'close', 'volume'])
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            if len(df) > 500:
                df = df.tail(500)
            
            return df
        else:
            logger.warning(f"No candle data for {symbol}: {response}")
            return None
    except Exception as e:
        logger.exception(f"Failed to fetch candles for {symbol}: {e}")
        return None

def create_candlestick_chart(df, symbol, spot_price):
    """Create candlestick chart"""
    try:
        fig, ax = plt.subplots(figsize=(16, 9), facecolor='white')
        ax.set_facecolor('white')
        
        for idx, row in df.iterrows():
            open_price = row['open']
            high_price = row['high']
            low_price = row['low']
            close_price = row['close']
            
            color = '#26a69a' if close_price >= open_price else '#ef5350'
            
            ax.plot([idx, idx], [low_price, high_price], color=color, linewidth=1)
            
            body_height = abs(close_price - open_price)
            body_bottom = min(open_price, close_price)
            rect = Rectangle((idx - 0.4, body_bottom), 0.8, body_height, 
                           facecolor=color, edgecolor=color, linewidth=0)
            ax.add_patch(rect)
        
        ax.set_xlabel('Time', fontsize=12, fontweight='bold')
        ax.set_ylabel('Price', fontsize=12, fontweight='bold')
        ax.set_title(f'{symbol} - 15 Min Chart | Spot: ₹{spot_price:,.2f}', 
                    fontsize=16, fontweight='bold', pad=20)
        
        ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.5)
        ax.set_axisbelow(True)
        
        step = max(1, len(df) // 10)
        xticks = range(0, len(df), step)
        xticklabels = [df.iloc[i]['timestamp'].strftime('%d-%b %H:%M') for i in xticks]
        ax.set_xticks(xticks)
        ax.set_xticklabels(xticklabels, rotation=45, ha='right')
        
        plt.tight_layout()
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100, facecolor='white')
        buf.seek(0)
        plt.close(fig)
        
        return buf.getvalue()
    except Exception as e:
        logger.exception(f"Failed to create chart: {e}")
        return None

def format_volume(vol):
    """Format volume in readable format"""
    if vol >= 10000000:
        return f"{vol/10000000:.1f}Cr"
    elif vol >= 100000:
        return f"{vol/100000:.1f}L"
    elif vol >= 1000:
        return f"{vol/1000:.0f}k"
    return str(vol)

def format_nifty50_summary(stock_prices):
    """Format Nifty 50 stocks summary"""
    msg = []
    msg.append("📈 <b>NIFTY 50 STOCKS</b>\n")
    
    # Sort by pct change
    sorted_stocks = sorted(stock_prices.items(), key=lambda x: x[1].get('pct_change', 0), reverse=True)
    
    msg.append("<code>SYMBOL       LTP    CHG%   VOL</code>")
    msg.append("─" * 40)
    
    for symbol, data in sorted_stocks:
        ltp = data.get('ltp', 0)
        pct = data.get('pct_change', 0)
        vol = data.get('volume', 0)
        
        emoji = "🟢" if pct > 0 else "🔴" if pct < 0 else "⚪"
        vol_str = format_volume(vol)
        
        msg.append(f"<code>{emoji} {symbol:<10} {ltp:>7.1f} {pct:>6.2f}% {vol_str:>6}</code>")
    
    msg.append("─" * 40)
    msg.append(f"🕐 {time.strftime('%H:%M:%S')}")
    
    return "\n".join(msg)

def format_option_chain_detailed(symbol, spot_price, expiry, option_data, market_data, lot_size, strike_gap):
    """Format detailed option chain with volume and OI changes"""
    msg = []
    msg.append(f"📊 <b>{symbol} OPTION CHAIN</b>")
    msg.append(f"💰 Spot: ₹{spot_price:,.1f} | 📅 {expiry} | Lot: {lot_size}\n")
    
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
    
    msg.append("<code>──── CALL ────     STRIKE     ──── PUT ────</code>")
    msg.append("<code>OI    Vol  LTP              LTP  Vol   OI</code>")
    msg.append("─" * 45)
    
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
        ce_oi_chg = ce.get('oi_change', 0)
        
        pe_ltp = pe.get('ltp', 0)
        pe_oi = pe.get('oi', 0)
        pe_vol = pe.get('volume', 0)
        pe_oi_chg = pe.get('oi_change', 0)
        
        total_ce_oi += ce_oi
        total_pe_oi += pe_oi
        total_ce_vol += ce_vol
        total_pe_vol += pe_vol
        
        # Format with OI change indicators
        ce_oi_str = f"{format_volume(ce_oi)}"
        pe_oi_str = f"{format_volume(pe_oi)}"
        
        if ce_oi_chg > 1000:
            ce_oi_str += "⬆️"
        elif ce_oi_chg < -1000:
            ce_oi_str += "⬇️"
            
        if pe_oi_chg > 1000:
            pe_oi_str += "⬆️"
        elif pe_oi_chg < -1000:
            pe_oi_str += "⬇️"
        
        ce_vol_str = format_volume(ce_vol) if ce_vol > 0 else "-"
        pe_vol_str = format_volume(pe_vol) if pe_vol > 0 else "-"
        
        ce_str = f"{ce_oi_str:>7} {ce_vol_str:>5} {ce_ltp:>4.0f}" if ce_ltp > 0 else "                  "
        pe_str = f"{pe_ltp:>4.0f} {pe_vol_str:>5} {pe_oi_str:>7}" if pe_ltp > 0 else "                  "
        
        # Highlight ATM
        strike_str = f"{int(strike):>6}"
        if abs(strike - spot_price) < strike_gap:
            strike_str = f">{strike_str}<"
        
        msg.append(f"<code>{ce_str}  {strike_str}  {pe_str}</code>")
    
    msg.append("─" * 45)
    
    if total_ce_oi > 0 or total_pe_oi > 0:
        pcr = total_pe_oi / total_ce_oi if total_ce_oi > 0 else 0
        msg.append(f"<b>PCR:</b> {pcr:.2f}")
        msg.append(f"<b>Total OI:</b> CE {format_volume(total_ce_oi)} | PE {format_volume(total_pe_oi)}")
        msg.append(f"<b>Total Vol:</b> CE {format_volume(total_ce_vol)} | PE {format_volume(total_pe_vol)}")
    
    msg.append(f"\n🕐 {time.strftime('%H:%M:%S')}")
    
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

    tele_send_http(TELE_CHAT_ID, "✅ <b>Advanced Trading Bot Started!</b>\n\n📊 Nifty 50 Stocks\n📈 Option Chains (Nifty, BankNifty, FinNifty)\n⏱ Updates every 5 min\n\n⏳ Loading...")
    
    instruments = download_instruments(smartApi)
    if not instruments:
        logger.error("No instruments")
        return
    
    # Find expiries for indices
    expiries = {}
    for symbol, config in INDICES_CONFIG.items():
        exp = find_nearest_expiry(instruments, symbol, config['exch_seg'], config['name_in_instruments'])
        if exp:
            expiries[symbol] = exp
    
    iteration = 0
    while True:
        try:
            iteration += 1
            logger.info(f"\n{'='*50}\n🔄 Iteration #{iteration}\n{'='*50}")
            
            # 1. Nifty 50 Stocks
            stock_prices = get_stock_prices(smartApi)
            if stock_prices:
                msg = format_nifty50_summary(stock_prices)
                tele_send_http(TELE_CHAT_ID, msg)
                time.sleep(2)
            
            # 2. Index prices
            index_prices = get_index_prices(smartApi)
            
            # 3. Option chains for each index
            for symbol, config in INDICES_CONFIG.items():
                if symbol not in expiries:
                    logger.warning(f"No expiry for {symbol}")
                    continue
                    
                if symbol not in index_prices:
                    logger.warning(f"No spot price for {symbol}")
                    continue
                
                spot_price = index_prices[symbol]
                expiry = expiries[symbol]
                
                logger.info(f"Processing {symbol} option chain...")
                
                option_tokens = find_option_tokens(
                    instruments, symbol, expiry, spot_price,
                    config['strike_gap'], config['strikes_count'],
                    config['exch_seg'], config['name_in_instruments']
                )
                
                if not option_tokens:
                    logger.warning(f"No option tokens for {symbol}")
                    continue
                
                market_data = get_option_data(smartApi, option_tokens, config['exch_seg'])
                
                if not market_data:
                    logger.warning(f"No market data for {symbol}")
                    continue
                
                msg = format_option_chain_detailed(
                    symbol, spot_price, expiry, option_tokens, 
                    market_data, config['lot_size'], config['strike_gap']
                )
                tele_send_http(TELE_CHAT_ID, msg)
                logger.info(f"✅ {symbol} option chain sent")
                time.sleep(3)
                
                # Send candlestick chart
                candle_df = get_historical_candles(smartApi, symbol, config['spot_token'], config['exchange'])
                if candle_df is not None and len(candle_df) > 0:
                    chart_bytes = create_candlestick_chart(candle_df, symbol, spot_price)
                    if chart_bytes:
                        tele_send_photo(TELE_CHAT_ID, chart_bytes, f"📊 {symbol} 15-Min Chart")
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
        'service': 'Advanced Angel Trading Bot',
        'bot_alive': thread.is_alive(),
        'features': {
            'nifty50_stocks': len(NIFTY50_STOCKS),
            'indices': list(INDICES_CONFIG.keys()),
            'option_chains': 'Full data with volume & OI tracking'
        },
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'thread': thread.is_alive()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)))
