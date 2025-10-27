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
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import matplotlib.dates as mdates
from PIL import Image, ImageDraw, ImageFont
import io

SmartConnect = None
try:
    from smartapi import SmartConnect as _SC
    SmartConnect = _SC
    logging.info("SmartConnect imported!")
except Exception as e:
    logging.error(f"SmartConnect import failed: {e}")

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

app = Flask(__name__)

# ALL INDICES + STOCKS with Options
SYMBOLS_CONFIG = {
    'NIFTY': {
        'spot_token': '99926000',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 50,
        'strikes_count': 25,
        'lot_size': 25,
        'name_in_instruments': 'NIFTY',
        'candle_interval': 'FIVE_MINUTE'
    },
    'BANKNIFTY': {
        'spot_token': '99926009',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 100,
        'strikes_count': 25,
        'lot_size': 15,
        'name_in_instruments': 'BANKNIFTY',
        'candle_interval': 'FIVE_MINUTE'
    },
    'FINNIFTY': {
        'spot_token': '99926074',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 50,
        'strikes_count': 25,
        'lot_size': 25,
        'name_in_instruments': 'FINNIFTY',
        'candle_interval': 'FIVE_MINUTE'
    },
    'MIDCPNIFTY': {
        'spot_token': '99926037',
        'exchange': 'NSE',
        'exch_seg': 'NFO',
        'strike_gap': 25,
        'strikes_count': 25,
        'lot_size': 75,
        'name_in_instruments': 'MIDCPNIFTY',
        'candle_interval': 'FIVE_MINUTE'
    },
    'SENSEX': {
        'spot_token': '99919000',
        'exchange': 'BSE',
        'exch_seg': 'BFO',
        'strike_gap': 100,
        'strikes_count': 25,
        'lot_size': 10,
        'name_in_instruments': 'SENSEX',
        'candle_interval': 'FIVE_MINUTE'
    },
}

previous_oi = defaultdict(dict)

def tele_send_message(chat_id: str, text: str):
    """Send text message to Telegram"""
    try:
        url = f"https://api.telegram.org/bot{TELE_TOKEN}/sendMessage"
        data = {'chat_id': chat_id, 'text': text, 'parse_mode': 'HTML'}
        r = requests.post(url, data=data, timeout=30)
        return r.status_code == 200
    except Exception as e:
        logger.exception(f'Message send failed: {e}')
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
    return smartApi

def download_instruments():
    try:
        logger.info("📥 Downloading instruments...")
        url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            instruments = response.json()
            logger.info(f"✅ {len(instruments)} instruments")
            return instruments
        return None
    except Exception as e:
        logger.exception(f"Instruments failed: {e}")
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
        
        if future_expiries:
            future_expiries.sort()
            return future_expiries[0][1]
        return None
    except:
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
                            }
            except Exception as e:
                logger.error(f"Batch error: {e}")
            
            time.sleep(0.3)
        
        return result
    except Exception as e:
        logger.exception(f"Option data failed: {e}")
        return {}

def get_spot_price(smartApi, token, exchange):
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
    except:
        return 0

def get_candlestick_data(smartApi, token, exchange, interval='FIVE_MINUTE', candles=200):
    """Fetch historical candlestick data from Angel One"""
    try:
        to_date = datetime.now()
        
        interval_minutes = {
            'ONE_MINUTE': 1,
            'FIVE_MINUTE': 5,
            'FIFTEEN_MINUTE': 15,
            'ONE_HOUR': 60,
            'ONE_DAY': 1440
        }
        
        minutes_needed = candles * interval_minutes.get(interval, 5)
        days_needed = (minutes_needed // (6.5 * 60)) + 5
        from_date = to_date - timedelta(days=days_needed)
        
        params = {
            "exchange": exchange,
            "symboltoken": token,
            "interval": interval,
            "fromdate": from_date.strftime("%Y-%m-%d %H:%M"),
            "todate": to_date.strftime("%Y-%m-%d %H:%M")
        }
        
        logger.info(f"Fetching candles: {interval}")
        candle_data = smartApi.getCandleData(params)
        
        if candle_data and candle_data.get('status') and candle_data.get('data'):
            data = candle_data['data']
            df = pd.DataFrame(data, columns=['timestamp', 'open', 'high', 'low', 'close', 'volume'])
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.sort_values('timestamp').tail(candles)
            logger.info(f"✅ Got {len(df)} candles")
            return df
        
        return None
    except Exception as e:
        logger.exception(f"Candlestick fetch failed: {e}")
        return None

def detect_candlestick_patterns(df):
    """Detect candlestick patterns and return alerts"""
    if df is None or len(df) < 3:
        return []
    
    alerts = []
    
    # Get last 3 candles
    last_candles = df.tail(3).reset_index(drop=True)
    
    if len(last_candles) < 3:
        return alerts
    
    # Current candle (most recent)
    c0 = last_candles.iloc[2]
    c1 = last_candles.iloc[1]  # Previous
    c2 = last_candles.iloc[0]  # 2 candles back
    
    # Calculate body and shadow sizes
    c0_body = abs(c0['close'] - c0['open'])
    c0_range = c0['high'] - c0['low']
    c0_upper_shadow = c0['high'] - max(c0['open'], c0['close'])
    c0_lower_shadow = min(c0['open'], c0['close']) - c0['low']
    
    c1_body = abs(c1['close'] - c1['open'])
    c1_range = c1['high'] - c1['low']
    
    # 1. BULLISH ENGULFING
    if (c1['close'] < c1['open'] and  # Previous red
        c0['close'] > c0['open'] and  # Current green
        c0['open'] < c1['close'] and  # Opens below prev close
        c0['close'] > c1['open'] and  # Closes above prev open
        c0_body > c1_body * 1.2):     # Bigger body
        alerts.append({
            'pattern': '🟢 BULLISH ENGULFING',
            'signal': 'BUY',
            'strength': 'Strong',
            'description': 'Green candle engulfs previous red candle'
        })
    
    # 2. BEARISH ENGULFING
    if (c1['close'] > c1['open'] and  # Previous green
        c0['close'] < c0['open'] and  # Current red
        c0['open'] > c1['close'] and  # Opens above prev close
        c0['close'] < c1['open'] and  # Closes below prev open
        c0_body > c1_body * 1.2):     # Bigger body
        alerts.append({
            'pattern': '🔴 BEARISH ENGULFING',
            'signal': 'SELL',
            'strength': 'Strong',
            'description': 'Red candle engulfs previous green candle'
        })
    
    # 3. HAMMER (Bullish reversal)
    if (c0_body > 0 and
        c0_lower_shadow > c0_body * 2 and  # Long lower shadow
        c0_upper_shadow < c0_body * 0.3 and  # Small upper shadow
        c0['close'] > c0['open']):  # Green candle
        alerts.append({
            'pattern': '🔨 HAMMER',
            'signal': 'BUY',
            'strength': 'Medium',
            'description': 'Bullish reversal - Long lower shadow'
        })
    
    # 4. SHOOTING STAR (Bearish reversal)
    if (c0_body > 0 and
        c0_upper_shadow > c0_body * 2 and  # Long upper shadow
        c0_lower_shadow < c0_body * 0.3 and  # Small lower shadow
        c0['close'] < c0['open']):  # Red candle
        alerts.append({
            'pattern': '⭐ SHOOTING STAR',
            'signal': 'SELL',
            'strength': 'Medium',
            'description': 'Bearish reversal - Long upper shadow'
        })
    
    # 5. DOJI (Indecision)
    if c0_body < c0_range * 0.1:  # Very small body
        alerts.append({
            'pattern': '➕ DOJI',
            'signal': 'NEUTRAL',
            'strength': 'Weak',
            'description': 'Market indecision - Wait for confirmation'
        })
    
    # 6. MORNING STAR (3-candle bullish reversal)
    if (c2['close'] < c2['open'] and  # First red
        abs(c1['close'] - c1['open']) < c1_range * 0.3 and  # Middle small body (star)
        c0['close'] > c0['open'] and  # Last green
        c0['close'] > (c2['open'] + c2['close']) / 2):  # Closes above midpoint of first
        alerts.append({
            'pattern': '🌅 MORNING STAR',
            'signal': 'BUY',
            'strength': 'Very Strong',
            'description': 'Three-candle bullish reversal pattern'
        })
    
    # 7. EVENING STAR (3-candle bearish reversal)
    if (c2['close'] > c2['open'] and  # First green
        abs(c1['close'] - c1['open']) < c1_range * 0.3 and  # Middle small body (star)
        c0['close'] < c0['open'] and  # Last red
        c0['close'] < (c2['open'] + c2['close']) / 2):  # Closes below midpoint of first
        alerts.append({
            'pattern': '🌇 EVENING STAR',
            'signal': 'SELL',
            'strength': 'Very Strong',
            'description': 'Three-candle bearish reversal pattern'
        })
    
    # 8. THREE WHITE SOLDIERS (Strong bullish)
    if (len(last_candles) >= 3 and
        all(c['close'] > c['open'] for _, c in last_candles.iterrows()) and  # All green
        all(last_candles.iloc[i]['close'] > last_candles.iloc[i-1]['close'] 
            for i in range(1, len(last_candles)))):  # Each closes higher
        alerts.append({
            'pattern': '⬆️⬆️⬆️ THREE WHITE SOLDIERS',
            'signal': 'STRONG BUY',
            'strength': 'Very Strong',
            'description': 'Three consecutive bullish candles'
        })
    
    # 9. THREE BLACK CROWS (Strong bearish)
    if (len(last_candles) >= 3 and
        all(c['close'] < c['open'] for _, c in last_candles.iterrows()) and  # All red
        all(last_candles.iloc[i]['close'] < last_candles.iloc[i-1]['close'] 
            for i in range(1, len(last_candles)))):  # Each closes lower
        alerts.append({
            'pattern': '⬇️⬇️⬇️ THREE BLACK CROWS',
            'signal': 'STRONG SELL',
            'strength': 'Very Strong',
            'description': 'Three consecutive bearish candles'
        })
    
    # 10. SPINNING TOP (Indecision with equal shadows)
    if (c0_body > 0 and
        c0_body < c0_range * 0.3 and  # Small body
        c0_upper_shadow > c0_body * 0.8 and
        c0_lower_shadow > c0_body * 0.8):  # Both shadows present
        alerts.append({
            'pattern': '🌀 SPINNING TOP',
            'signal': 'NEUTRAL',
            'strength': 'Weak',
            'description': 'Indecision - Equal upper and lower shadows'
        })
    
    return alerts

def create_candlestick_chart(symbol, df, spot_price):
    """Create beautiful candlestick chart using pure matplotlib"""
    try:
        if df is None or len(df) == 0:
            return None
        
        df = df.copy()
        df['date_num'] = mdates.date2num(df['timestamp'])
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 8), 
                                        gridspec_kw={'height_ratios': [3, 1]},
                                        facecolor='#0a0a0a')
        
        ax1.set_facecolor('#0a0a0a')
        
        # Draw candlesticks
        for idx, row in df.iterrows():
            color = '#26a69a' if row['close'] >= row['open'] else '#ef5350'
            
            # Wick (High-Low line)
            ax1.plot([row['date_num'], row['date_num']], 
                    [row['low'], row['high']], 
                    color=color, linewidth=1, alpha=0.8)
            
            # Body (Open-Close rectangle)
            height = abs(row['close'] - row['open'])
            if height == 0:
                height = 0.01
            bottom = min(row['open'], row['close'])
            
            rect = Rectangle((row['date_num'] - 0.0002, bottom), 
                           0.0004, height,
                           facecolor=color, edgecolor=color, alpha=0.9)
            ax1.add_patch(rect)
        
        # Current price line
        ax1.axhline(y=spot_price, color='#ffeb3b', linestyle='--', 
                   linewidth=1.5, alpha=0.7, label=f'LTP: ₹{spot_price:,.2f}')
        
        # Moving averages
        if len(df) >= 20:
            df['sma20'] = df['close'].rolling(window=20).mean()
            ax1.plot(df['date_num'], df['sma20'], color='#2196f3', 
                    linewidth=1.5, alpha=0.7, label='SMA 20')
        
        if len(df) >= 50:
            df['sma50'] = df['close'].rolling(window=50).mean()
            ax1.plot(df['date_num'], df['sma50'], color='#ff9800', 
                    linewidth=1.5, alpha=0.7, label='SMA 50')
        
        # Format main chart
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%d-%b %H:%M'))
        ax1.xaxis.set_major_locator(mdates.AutoDateLocator())
        plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right', color='white')
        ax1.tick_params(colors='white')
        for spine in ax1.spines.values():
            spine.set_color('#333333')
        
        ax1.set_title(f'{symbol} - Last 200 Candles (5min)', 
                     color='#00ff00', fontsize=16, fontweight='bold', pad=20)
        ax1.set_ylabel('Price (₹)', color='white', fontsize=12)
        ax1.legend(loc='upper left', facecolor='#1a1a1a', edgecolor='#333333', 
                  labelcolor='white', fontsize=10)
        ax1.grid(True, alpha=0.15, color='#333333')
        
        # Volume chart
        ax2.set_facecolor('#0a0a0a')
        colors = ['#26a69a' if c >= o else '#ef5350' 
                 for c, o in zip(df['close'], df['open'])]
        ax2.bar(df['date_num'], df['volume'], color=colors, alpha=0.6, width=0.0004)
        
        ax2.xaxis.set_major_formatter(mdates.DateFormatter('%d-%b %H:%M'))
        ax2.xaxis.set_major_locator(mdates.AutoDateLocator())
        plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right', color='white')
        ax2.tick_params(colors='white')
        for spine in ax2.spines.values():
            spine.set_color('#333333')
        
        ax2.set_ylabel('Volume', color='white', fontsize=10)
        ax2.grid(True, alpha=0.15, color='#333333')
        
        # Stats
        latest = df.iloc[-1]
        change = latest['close'] - df.iloc[0]['open']
        change_pct = (change / df.iloc[0]['open']) * 100
        
        stats_text = (f"O: ₹{latest['open']:.2f} | H: ₹{latest['high']:.2f} | "
                     f"L: ₹{latest['low']:.2f} | C: ₹{latest['close']:.2f} | "
                     f"Change: ₹{change:+.2f} ({change_pct:+.2f}%)")
        
        fig.text(0.5, 0.02, stats_text, ha='center', color='white', 
                fontsize=10, bbox=dict(boxstyle='round', facecolor='#1a1a1a', alpha=0.8))
        
        plt.tight_layout()
        
        buf = io.BytesIO()
        plt.savefig(buf, format='PNG', facecolor='#0a0a0a', dpi=100)
        buf.seek(0)
        plt.close()
        
        return buf.getvalue()
        
    except Exception as e:
        logger.exception(f"Candlestick chart failed: {e}")
        return None

def format_volume(vol):
    if vol >= 10000000:
        return f"{vol/10000000:.1f}Cr"
    elif vol >= 100000:
        return f"{vol/100000:.1f}L"
    elif vol >= 1000:
        return f"{vol/1000:.0f}k"
    return str(vol)

def create_option_chain_image(symbol, spot_price, expiry, option_data, market_data, lot_size, strike_gap):
    """Create beautiful PNG image of option chain"""
    try:
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
        
        total_ce_oi = 0
        total_pe_oi = 0
        
        filtered_strikes = []
        for strike in sorted(strikes.keys()):
            if abs(strike - spot_price) <= (strike_gap * 12):
                filtered_strikes.append(strike)
                ce = strikes[strike].get('CE', {})
                pe = strikes[strike].get('PE', {})
                total_ce_oi += ce.get('oi', 0)
                total_pe_oi += pe.get('oi', 0)
        
        width = 800
        row_height = 25
        header_height = 100
        footer_height = 80
        rows = len(filtered_strikes)
        height = header_height + (rows * row_height) + footer_height
        
        img = Image.new('RGB', (width, height), color='#0a0a0a')
        draw = ImageDraw.Draw(img)
        
        try:
            font_header = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 16)
            font_title = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 14)
            font_data = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 11)
            font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 10)
        except:
            font_header = ImageFont.load_default()
            font_title = ImageFont.load_default()
            font_data = ImageFont.load_default()
            font_small = ImageFont.load_default()
        
        draw.rectangle([0, 0, width, header_height], fill='#1a1a1a')
        draw.text((width//2, 20), f"{symbol} OPTION CHAIN", fill='#00ff00', font=font_header, anchor='mt')
        draw.text((width//2, 50), f"Spot: ₹{spot_price:,.2f} | {expiry} | Lot: {lot_size}", 
                 fill='#ffffff', font=font_title, anchor='mt')
        draw.text((width//2, 75), f"Time: {time.strftime('%d-%b %H:%M:%S')}", 
                 fill='#888888', font=font_small, anchor='mt')
        
        y = header_height + 5
        draw.text((100, y), "CALL", fill='#26a69a', font=font_title, anchor='mt')
        draw.text((width//2, y), "STRIKE", fill='#ffffff', font=font_title, anchor='mt')
        draw.text((width-100, y), "PUT", fill='#ef5350', font=font_title, anchor='mt')
        
        y += 25
        draw.line([(0, y), (width, y)], fill='#333333', width=2)
        
        y += 5
        draw.text((50, y), "OI", fill='#888888', font=font_small, anchor='mt')
        draw.text((150, y), "Vol", fill='#888888', font=font_small, anchor='mt')
        draw.text((230, y), "LTP", fill='#888888', font=font_small, anchor='mt')
        
        draw.text((570, y), "LTP", fill='#888888', font=font_small, anchor='mt')
        draw.text((650, y), "Vol", fill='#888888', font=font_small, anchor='mt')
        draw.text((750, y), "OI", fill='#888888', font=font_small, anchor='mt')
        
        y += 20
        
        for strike in filtered_strikes:
            ce = strikes[strike].get('CE', {})
            pe = strikes[strike].get('PE', {})
            
            if abs(strike - spot_price) <= strike_gap:
                draw.rectangle([0, y, width, y + row_height], fill='#1a1a2e')
            
            ce_oi = format_volume(ce.get('oi', 0)) if ce.get('oi', 0) > 0 else "-"
            ce_vol = format_volume(ce.get('volume', 0)) if ce.get('volume', 0) > 0 else "-"
            ce_ltp = f"{ce.get('ltp', 0):.0f}" if ce.get('ltp', 0) > 0 else "-"
            
            draw.text((70, y + row_height//2), ce_oi, fill='#26a69a', font=font_data, anchor='mm')
            draw.text((170, y + row_height//2), ce_vol, fill='#26a69a', font=font_data, anchor='mm')
            draw.text((250, y + row_height//2), ce_ltp, fill='#26a69a', font=font_data, anchor='mm')
            
            strike_color = '#ffff00' if abs(strike - spot_price) <= strike_gap else '#ffffff'
            draw.text((width//2, y + row_height//2), f"{int(strike)}", fill=strike_color, font=font_data, anchor='mm')
            
            pe_ltp = f"{pe.get('ltp', 0):.0f}" if pe.get('ltp', 0) > 0 else "-"
            pe_vol = format_volume(pe.get('volume', 0)) if pe.get('volume', 0) > 0 else "-"
            pe_oi = format_volume(pe.get('oi', 0)) if pe.get('oi', 0) > 0 else "-"
            
            draw.text((550, y + row_height//2), pe_ltp, fill='#ef5350', font=font_data, anchor='mm')
            draw.text((630, y + row_height//2), pe_vol, fill='#ef5350', font=font_data, anchor='mm')
            draw.text((730, y + row_height//2), pe_oi, fill='#ef5350', font=font_data, anchor='mm')
            
            y += row_height
        
        draw.line([(0, y), (width, y)], fill='#333333', width=2)
        y += 10
        
        pcr = total_pe_oi / total_ce_oi if total_ce_oi > 0 else 0
        draw.text((width//2, y), f"PCR: {pcr:.2f}", fill='#ffffff', font=font_title, anchor='mt')
        y += 25
        draw.text((width//2, y), f"Total OI - CE: {format_volume(total_ce_oi)} | PE: {format_volume(total_pe_oi)}", 
                 fill='#888888', font=font_small, anchor='mt')
        
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        
        return buf.getvalue()
        
    except Exception as e:
        logger.exception(f"Image creation failed: {e}")
        return None

def bot_loop():
    if not all([API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET, TELE_TOKEN, TELE_CHAT_ID]):
        logger.error('❌ Missing env variables')
        return

    try:
        smartApi = login_and_setup(API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET)
    except Exception as e:
        logger.exception('❌ Login failed')
        return

    instruments = download_instruments()
    if not instruments:
        logger.error("No instruments")
        return
    
    expiries = {}
    for symbol, config in SYMBOLS_CONFIG.items():
        exp = find_nearest_expiry(instruments, symbol, config['exch_seg'], config['name_in_instruments'])
        if exp:
            expiries[symbol] = exp
            logger.info(f"✅ {symbol}: {exp}")
    
    iteration = 0
    while True:
        try:
            iteration += 1
            logger.info(f"\n{'='*50}\n🔄 Iteration #{iteration}\n{'='*50}")
            
            for symbol, config in SYMBOLS_CONFIG.items():
                logger.info(f"\n--- {symbol} ---")
                
                if symbol not in expiries:
                    logger.warning(f"No expiry for {symbol}")
                    continue
                
                spot_price = get_spot_price(smartApi, config['spot_token'], config['exchange'])
                if spot_price == 0:
                    logger.warning(f"No spot for {symbol}")
                    continue
                
                logger.info(f"Spot: ₹{spot_price:,.2f}")
                
                # Candlestick Chart with Pattern Detection
                logger.info(f"📊 Fetching candlestick data (200 candles, 5min)...")
                candle_df = get_candlestick_data(
                    smartApi, 
                    config['spot_token'], 
                    config['exchange'],
                    'FIVE_MINUTE',
                    200
                )
                
                if candle_df is not None and len(candle_df) > 0:
                    # Detect patterns
                    patterns = detect_candlestick_patterns(candle_df)
                    
                    # Create chart
                    candle_img = create_candlestick_chart(symbol, candle_df, spot_price)
                    
                    if candle_img:
                        candle_caption = (f"📈 {symbol} Candlestick Chart\n"
                                        f"💰 LTP: ₹{spot_price:,.2f}\n"
                                        f"⏰ 5 Minute Timeframe\n"
                                        f"📊 Last 200 Candles\n"
                                        f"🕐 {time.strftime('%d-%b %H:%M')}")
                        
                        tele_send_photo(TELE_CHAT_ID, candle_img, candle_caption)
                        logger.info(f"✅ Candlestick sent for {symbol}")
                        time.sleep(2)
                    
                    # Send pattern alerts if detected
                    if patterns:
                        alert_msg = f"🚨 <b>{symbol} PATTERN ALERTS</b> 🚨\n"
                        alert_msg += f"💰 Price: ₹{spot_price:,.2f}\n"
                        alert_msg += f"⏰ {time.strftime('%d-%b %H:%M:%S')}\n\n"
                        
                        for pattern in patterns:
                            signal_emoji = '📈' if 'BUY' in pattern['signal'] else '📉' if 'SELL' in pattern['signal'] else '⚪'
                            alert_msg += f"{signal_emoji} <b>{pattern['pattern']}</b>\n"
                            alert_msg += f"   Signal: {pattern['signal']}\n"
                            alert_msg += f"   Strength: {pattern['strength']}\n"
                            alert_msg += f"   {pattern['description']}\n\n"
                        
                        tele_send_message(TELE_CHAT_ID, alert_msg)
                        logger.info(f"✅ Pattern alerts sent: {len(patterns)} patterns")
                        time.sleep(2)
                
                # Option Chain
                logger.info(f"🔗 Fetching option chain...")
                
                option_tokens = find_option_tokens(
                    instruments, symbol, expiries[symbol], spot_price,
                    config['strike_gap'], config['strikes_count'],
                    config['exch_seg'], config['name_in_instruments']
                )
                
                if not option_tokens:
                    logger.warning(f"No options for {symbol}")
                    continue
                
                logger.info(f"Found {len(option_tokens)} options")
                
                market_data = get_option_data(smartApi, option_tokens, config['exch_seg'])
                
                if not market_data:
                    logger.warning(f"No market data for {symbol}")
                    continue
                
                logger.info(f"Got data for {len(market_data)} tokens")
                
                oc_img = create_option_chain_image(
                    symbol, spot_price, expiries[symbol], option_tokens,
                    market_data, config['lot_size'], config['strike_gap']
                )
                
                if oc_img:
                    oc_caption = (f"🔗 {symbol} Option Chain\n"
                                 f"💰 ₹{spot_price:,.2f} | {expiries[symbol]}\n"
                                 f"📦 Lot: {config['lot_size']}\n"
                                 f"🕐 {time.strftime('%d-%b %H:%M')}")
                    
                    tele_send_photo(TELE_CHAT_ID, oc_img, oc_caption)
                    logger.info(f"✅ Option chain sent for {symbol}")
                    time.sleep(3)
                
                time.sleep(2)
            
            logger.info(f"✅ Iteration done. Sleep {POLL_INTERVAL}s...")
            
        except Exception as e:
            logger.exception(f"Error: {e}")
        
        time.sleep(POLL_INTERVAL)

thread = threading.Thread(target=bot_loop, daemon=True)
thread.start()

@app.route('/')
def index():
    return jsonify({
        'service': 'Angel Option Chain + Candlestick Bot with Pattern Detection',
        'status': 'running',
        'symbols': list(SYMBOLS_CONFIG.keys()),
        'features': [
            'Option Chain PNG', 
            'Candlestick Charts (5min timeframe)',
            'Last 200 Candles',
            'Pattern Detection (10+ patterns)',
            'Automatic Telegram Alerts'
        ],
        'patterns_detected': [
            'Bullish/Bearish Engulfing',
            'Hammer & Shooting Star',
            'Doji & Spinning Top',
            'Morning/Evening Star',
            'Three White Soldiers/Black Crows'
        ],
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'thread': thread.is_alive()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)))
