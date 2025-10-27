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

# Config
API_KEY = os.getenv('SMARTAPI_API_KEY')
CLIENT_ID = os.getenv('SMARTAPI_CLIENT_ID')
PASSWORD = os.getenv('SMARTAPI_PASSWORD')
TOTP_SECRET = os.getenv('SMARTAPI_TOTP_SECRET')
TELE_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELE_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL') or 300)

REQUIRED = [API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET, TELE_TOKEN, TELE_CHAT_ID]

app = Flask(__name__)

# NIFTY 50 STOCKS
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
}

# Indices
INDICES_CONFIG = {
    'NIFTY': {
        'spot_token': '99926000',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 50,
        'strikes_count': 41,
        'lot_size': 25,
        'name_in_instruments': 'NIFTY'
    },
    'BANKNIFTY': {
        'spot_token': '99926009',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 100,
        'strikes_count': 41,
        'lot_size': 15,
        'name_in_instruments': 'BANKNIFTY'
    },
    'FINNIFTY': {
        'spot_token': '99926074',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 50,
        'strikes_count': 41,
        'lot_size': 25,
        'name_in_instruments': 'FINNIFTY'
    }
}

previous_oi = defaultdict(dict)

def tele_send_http(chat_id: str, text: str):
    try:
        url = f"https://api.telegram.org/bot{TELE_TOKEN}/sendMessage"
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        r = requests.post(url, json=payload, timeout=10)
        return r.status_code == 200
    except Exception as e:
        logger.exception(f'Telegram send failed: {e}')
        return False

def tele_send_photo(chat_id: str, photo_bytes: bytes, caption: str = ""):
    try:
        url = f"https://api.telegram.org/bot{TELE_TOKEN}/sendPhoto"
        files = {'photo': ('chart.png', photo_bytes, 'image/png')}
        data = {'chat_id': chat_id, 'caption': caption, 'parse_mode': 'HTML'}
        r = requests.post(url, files=files, data=data, timeout=30)
        return r.status_code == 200
    except Exception as e:
        logger.exception(f'Photo send failed: {e}')
        return False

def login_and_setup(api_key, client_id, password, totp_secret):
    if SmartConnect is None:
        raise RuntimeError('SmartAPI SDK not available')
    smartApi = SmartConnect(api_key=api_key)
    totp = pyotp.TOTP(totp_secret).now()
    logger.info('Logging in...')
    data = smartApi.generateSession(client_id, password, totp)
    if not data or data.get('status') is False:
        raise RuntimeError(f"Login failed: {data}")
    logger.info(f"✅ Login successful!")
    return smartApi, data['data']['jwtToken'], data['data']['refreshToken'], None

def download_instruments():
    try:
        logger.info("📥 Downloading instruments...")
        url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            instruments = response.json()
            logger.info(f"✅ Downloaded {len(instruments)} instruments")
            return instruments
        return None
    except Exception as e:
        logger.exception(f"Instruments download failed: {e}")
        return None

def find_nearest_expiry(instruments, symbol, exch_seg, name_in_inst):
    try:
        expiries = set()
        for inst in instruments:
            if inst.get('name') == name_in_inst and inst.get('exch_seg') == exch_seg and inst.get('expiry'):
                expiries.add(inst.get('expiry'))
        
        if not expiries:
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
        return future_expiries[0][1]
    except Exception as e:
        logger.exception(f"Expiry find error: {e}")
        return None

def find_option_tokens(instruments, symbol, target_expiry, current_price, strike_gap, strikes_count, exch_seg, name_in_inst):
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
    
    return sorted(option_tokens, key=lambda x: (x['strike'], x['type']))

def get_option_data(smartApi, option_tokens, exch_seg):
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
        
        # Process in batches of 50
        for i in range(0, len(all_tokens), 50):
            batch = all_tokens[i:i+50]
            payload = {"mode": "FULL", "exchangeTokens": {exch_seg: batch}}
            
            try:
                response = requests.post(
                    'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
                    json=payload, headers=headers, timeout=20
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
                            }
                    else:
                        logger.warning(f"Batch {i} failed: {data}")
                else:
                    logger.warning(f"Batch {i} HTTP {response.status_code}")
            except Exception as e:
                logger.error(f"Batch {i} error: {e}")
            
            time.sleep(0.5)
        
        logger.info(f"Got data for {len(result)}/{len(all_tokens)} tokens")
        return result
    except Exception as e:
        logger.exception(f"Option data fetch failed: {e}")
        return {}

def get_spot_price(smartApi, token, exchange):
    """Get single spot price"""
    try:
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'X-PrivateKey': API_KEY
        }
        
        payload = {"mode": "FULL", "exchangeTokens": {exchange: [token]}}
        
        response = requests.post(
            'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
            json=payload, headers=headers, timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status'):
                items = data.get('data', {}).get('fetched', [])
                if items:
                    return float(items[0].get('ltp', 0))
        return 0
    except Exception as e:
        logger.error(f"Spot price error: {e}")
        return 0

def get_stock_prices(smartApi):
    try:
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'X-PrivateKey': API_KEY
        }
        
        all_tokens = [info['token'] for info in NIFTY50_STOCKS.values()]
        result = {}
        
        for i in range(0, len(all_tokens), 50):
            batch = all_tokens[i:i+50]
            payload = {"mode": "FULL", "exchangeTokens": {"NSE": batch}}
            
            try:
                response = requests.post(
                    'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
                    json=payload, headers=headers, timeout=15
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status'):
                        for item in data.get('data', {}).get('fetched', []):
                            token = item.get('symbolToken', '')
                            for symbol, info in NIFTY50_STOCKS.items():
                                if info['token'] == token:
                                    result[symbol] = {
                                        'ltp': float(item.get('ltp', 0)),
                                        'change': float(item.get('change', 0)),
                                        'pct_change': float(item.get('pChange', 0)),
                                        'volume': int(item.get('tradeVolume', 0))
                                    }
                                    break
            except Exception as e:
                logger.error(f"Stock batch error: {e}")
            
            time.sleep(0.5)
        
        return result
    except Exception as e:
        logger.exception(f"Stock prices failed: {e}")
        return {}

def get_historical_candles(smartApi, symbol, token, exchange):
    """Get LIVE candles - today's data included"""
    try:
        logger.info(f"📊 Fetching LIVE candles for {symbol}...")
        
        # Current time
        to_date = datetime.now()
        
        # From date - last 7 trading days for safety
        from_date = to_date - timedelta(days=10)
        
        params = {
            "exchange": exchange,
            "symboltoken": token,
            "interval": "FIFTEEN_MINUTE",
            "fromdate": from_date.strftime("%Y-%m-%d 09:15"),
            "todate": to_date.strftime("%Y-%m-%d %H:%M")
        }
        
        logger.info(f"Candle request: {from_date.strftime('%Y-%m-%d')} to {to_date.strftime('%Y-%m-%d %H:%M')}")
        
        response = smartApi.getCandleData(params)
        
        if response and response.get('status'):
            candles = response.get('data', [])
            
            if not candles:
                logger.warning(f"No candles returned for {symbol}")
                return None
            
            logger.info(f"✅ Got {len(candles)} candles for {symbol}")
            
            df = pd.DataFrame(candles, columns=['timestamp', 'open', 'high', 'low', 'close', 'volume'])
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Show last candle time
            if len(df) > 0:
                last_candle = df.iloc[-1]['timestamp']
                logger.info(f"Last candle: {last_candle.strftime('%Y-%m-%d %H:%M')}")
            
            # Keep last 100 candles for chart
            if len(df) > 100:
                df = df.tail(100)
            
            return df
        else:
            logger.warning(f"Candle API failed for {symbol}: {response}")
            return None
    except Exception as e:
        logger.exception(f"Candle fetch error for {symbol}: {e}")
        return None

def create_candlestick_chart(df, symbol, spot_price):
    try:
        fig, ax = plt.subplots(figsize=(16, 9), facecolor='#1e1e1e')
        ax.set_facecolor('#1e1e1e')
        
        # Reset index for plotting
        df_plot = df.reset_index(drop=True)
        
        for idx in range(len(df_plot)):
            row = df_plot.iloc[idx]
            open_price = row['open']
            high_price = row['high']
            low_price = row['low']
            close_price = row['close']
            
            color = '#26a69a' if close_price >= open_price else '#ef5350'
            
            # High-low line
            ax.plot([idx, idx], [low_price, high_price], color=color, linewidth=1.5)
            
            # Candle body
            body_height = abs(close_price - open_price)
            body_bottom = min(open_price, close_price)
            
            if body_height > 0:
                rect = Rectangle((idx - 0.4, body_bottom), 0.8, body_height, 
                               facecolor=color, edgecolor=color, linewidth=0)
                ax.add_patch(rect)
            else:
                # Doji
                ax.plot([idx - 0.4, idx + 0.4], [close_price, close_price], color=color, linewidth=2)
        
        # Styling
        ax.set_xlabel('Time', fontsize=12, fontweight='bold', color='white')
        ax.set_ylabel('Price', fontsize=12, fontweight='bold', color='white')
        
        # Title with last candle time
        last_time = df_plot.iloc[-1]['timestamp'].strftime('%d-%b %H:%M')
        ax.set_title(f'{symbol} Live Chart | Spot: ₹{spot_price:,.2f} | Last: {last_time}', 
                    fontsize=16, fontweight='bold', pad=20, color='white')
        
        # Grid
        ax.grid(True, alpha=0.2, linestyle='--', linewidth=0.5, color='gray')
        ax.set_axisbelow(True)
        
        # X-axis - show every 10th candle
        step = max(1, len(df_plot) // 10)
        xticks = list(range(0, len(df_plot), step))
        if xticks[-1] != len(df_plot) - 1:
            xticks.append(len(df_plot) - 1)
        
        xticklabels = [df_plot.iloc[i]['timestamp'].strftime('%d-%b\n%H:%M') for i in xticks]
        ax.set_xticks(xticks)
        ax.set_xticklabels(xticklabels, rotation=0, ha='center', color='white', fontsize=9)
        
        # Y-axis color
        ax.tick_params(axis='y', colors='white')
        
        # Spine colors
        for spine in ax.spines.values():
            spine.set_edgecolor('#444444')
        
        plt.tight_layout()
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100, facecolor='#1e1e1e')
        buf.seek(0)
        plt.close(fig)
        
        return buf.getvalue()
    except Exception as e:
        logger.exception(f"Chart creation failed: {e}")
        return None

def format_volume(vol):
    if vol >= 10000000:
        return f"{vol/10000000:.1f}Cr"
    elif vol >= 100000:
        return f"{vol/100000:.1f}L"
    elif vol >= 1000:
        return f"{vol/1000:.0f}k"
    return str(vol)

def format_nifty50_summary(stock_prices):
    msg = []
    msg.append("📈 <b>NIFTY 50 STOCKS (Top 10)</b>\n")
    
    sorted_stocks = sorted(stock_prices.items(), key=lambda x: x[1].get('pct_change', 0), reverse=True)
    
    msg.append("<code>SYMBOL     LTP    CHG%   VOL</code>")
    msg.append("─" * 38)
    
    for symbol, data in sorted_stocks[:10]:
        ltp = data.get('ltp', 0)
        pct = data.get('pct_change', 0)
        vol = data.get('volume', 0)
        
        emoji = "🟢" if pct > 0 else "🔴" if pct < 0 else "⚪"
        vol_str = format_volume(vol)
        
        msg.append(f"<code>{emoji} {symbol:<8} {ltp:>7.1f} {pct:>6.2f}% {vol_str:>6}</code>")
    
    msg.append("─" * 38)
    msg.append(f"🕐 {time.strftime('%d-%b %H:%M:%S')}")
    
    return "\n".join(msg)

def format_option_chain_detailed(symbol, spot_price, expiry, option_data, market_data, lot_size, strike_gap):
    msg = []
    msg.append(f"📊 <b>{symbol} OPTION CHAIN</b>")
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
    
    msg.append("<code>──── CALL ────   STRIKE   ──── PUT ────</code>")
    msg.append("<code>OI   Vol LTP            LTP Vol  OI</code>")
    msg.append("─" * 42)
    
    total_ce_oi = 0
    total_pe_oi = 0
    total_ce_vol = 0
    total_pe_vol = 0
    
    displayed_count = 0
    max_display = 25  # Show 25 strikes around ATM
    
    for strike in sorted(strikes.keys()):
        if abs(strike - spot_price) > (strike_gap * 13):
            continue
        
        displayed_count += 1
        if displayed_count > max_display:
            break
        
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
        
        ce_oi_str = format_volume(ce_oi) if ce_oi > 0 else "-"
        pe_oi_str = format_volume(pe_oi) if pe_oi > 0 else "-"
        ce_vol_str = format_volume(ce_vol) if ce_vol > 0 else "-"
        pe_vol_str = format_volume(pe_vol) if pe_vol > 0 else "-"
        
        ce_str = f"{ce_oi_str:>4} {ce_vol_str:>4} {ce_ltp:>3.0f}" if ce_ltp > 0 else "               "
        pe_str = f"{pe_ltp:>3.0f} {pe_vol_str:>4} {pe_oi_str:>4}" if pe_ltp > 0 else "               "
        
        strike_str = f"{int(strike):>6}"
        if abs(strike - spot_price) <= strike_gap:
            strike_str = f">{strike_str}<"
        
        msg.append(f"<code>{ce_str}  {strike_str}  {pe_str}</code>")
    
    msg.append("─" * 42)
    
    if total_ce_oi > 0 or total_pe_oi > 0:
        pcr = total_pe_oi / total_ce_oi if total_ce_oi > 0 else 0
        msg.append(f"<b>PCR:</b> {pcr:.2f}")
        msg.append(f"<b>OI:</b> CE {format_volume(total_ce_oi)} | PE {format_volume(total_pe_oi)}")
        msg.append(f"<b>Vol:</b> CE {format_volume(total_ce_vol)} | PE {format_volume(total_pe_vol)}")
    
    msg.append(f"\n🕐 {time.strftime('%d-%b %H:%M:%S')}")
    
    return "\n".join(msg)

def is_market_open():
    """Check if market is open"""
    now = datetime.now()
    
    # Weekend check
    if now.weekday() >= 5:
        return False
    
    # Market hours: 9:15 AM to 3:30 PM
    market_start = now.replace(hour=9, minute=15, second=0)
    market_end = now.replace(hour=15, minute=30, second=0)
    
    return market_start <= now <= market_end

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

    market_status = "🟢 LIVE" if is_market_open() else "🔴 CLOSED"
    tele_send_http(TELE_CHAT_ID, f"✅ <b>Advanced Trading Bot Started!</b>\n\n{market_status}\n📊 Stocks + Option Chains + Live Charts\n⏱ Updates every {POLL_INTERVAL//60} min\n\n⏳ Loading...")
    
    instruments = download_instruments()
    if not instruments:
        logger.error("No instruments")
        return
    
    expiries = {}
    for symbol, config in INDICES_CONFIG.items():
        exp = find_nearest_expiry(instruments, symbol, config['exch_seg'], config['name_in_instruments'])
        if exp:
            expiries[symbol] = exp
            logger.info(f"✅ {symbol} expiry: {exp}")
    
    iteration = 0
    while True:
        try:
            iteration += 1
            market_status = "🟢 LIVE" if is_market_open() else "🔴 CLOSED"
            logger.info(f"\n{'='*50}\n🔄 Iteration #{iteration} | {market_status}\n{'='*50}")
            
            # 1. Nifty 50 Stocks
            logger.info("Fetching stock prices...")
            stock_prices = get_stock_prices(smartApi)
            if stock_prices:
                msg = format_nifty50_summary(stock_prices)
                tele_send_http(TELE_CHAT_ID, msg)
                logger.info("✅ Stocks sent")
                time.sleep(2)
            
            # 2. Indices Option Chains + Charts
            for symbol, config in INDICES_CONFIG.items():
                logger.info(f"\n--- Processing {symbol} ---")
                
                if symbol not in expiries:
                    logger.warning(f"No expiry for {symbol}")
                    continue
                
                expiry = expiries[symbol]
                
                # Get spot price
                logger.info(f"Getting {symbol} spot price...")
                spot_price = get_spot_price(smartApi, config['spot_token'], config['exchange'])
                
                if spot_price == 0:
                    logger.warning(f"No spot price for {symbol}")
                    continue
                
                logger.info(f"✅ {symbol} Spot: {spot_price}")
                
                # Option Chain
                logger.info(f"Finding {symbol} option tokens...")
                option_tokens = find_option_tokens(
                    instruments, symbol, expiry, spot_price,
                    config['strike_gap'], config['strikes_count'],
                    config['exch_seg'], config['name_in_instruments']
                )
                
                if not option_tokens:
                    logger.warning(f"No option tokens for {symbol}")
                    continue
                
                logger.info(f"✅ Found {len(option_tokens)} options for {symbol}")
                
                logger.info(f"Fetching {symbol} market data...")
                market_data = get_option_data(smartApi, option_tokens, config['exch_seg'])
                
                if market_data:
                    logger.info(f"✅ Got data for {len(market_data)} options")
                    msg = format_option_chain_detailed(
                        symbol, spot_price, expiry, option_tokens, 
                        market_data, config['lot_size'], config['strike_gap']
                    )
                    tele_send_http(TELE_CHAT_ID, msg)
                    logger.info(f"✅ {symbol} option chain sent")
                    time.sleep(2)
                else:
                    logger.warning(f"No market data for {symbol}")
                
                # Live Chart
                logger.info(f"Fetching {symbol} live candles...")
                candle_df = get_historical_candles(smartApi, symbol, config['spot_token'], config['exchange'])
                
                if candle_df is not None and len(candle_df) > 0:
                    chart_bytes = create_candlestick_chart(candle_df, symbol, spot_price)
                    if chart_bytes:
                        caption = f"📊 {symbol} Live 15-Min Chart\n💰 Spot: ₹{spot_price:,.2f}\n🕐 {time.strftime('%d-%b %H:%M')}"
                        tele_send_photo(TELE_CHAT_ID, chart_bytes, caption)
                        logger.info(f"✅ {symbol} chart sent")
                        time.sleep(2)
                else:
                    logger.warning(f"No candle data for {symbol}")
                
                time.sleep(1)
            
            logger.info(f"✅ Iteration #{iteration} completed. Sleep {POLL_INTERVAL}s...")
            
        except Exception as e:
            logger.exception(f"❌ Error in iteration {iteration}: {e}")
            tele_send_http(TELE_CHAT_ID, f"⚠️ Error: {str(e)[:100]}")
        
        time.sleep(POLL_INTERVAL)

# Start bot
thread = threading.Thread(target=bot_loop, daemon=True)
thread.start()

@app.route('/')
def index():
    return jsonify({
        'service': 'Angel Trading Bot - Live Data',
        'status': 'running',
        'bot_alive': thread.is_alive(),
        'market_open': is_market_open(),
        'features': {
            'stocks': len(NIFTY50_STOCKS),
            'indices': list(INDICES_CONFIG.keys()),
            'updates': 'Option Chains + Live Charts',
            'interval': f'{POLL_INTERVAL//60} minutes'
        },
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'thread_alive': thread.is_alive(),
        'market_open': is_market_open()
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)))
