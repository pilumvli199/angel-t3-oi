import asyncio
import os
from telegram import Bot
import requests
from datetime import datetime, timedelta
import logging
import csv
import io
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import mplfinance as mpf
import pandas as pd
from smartapi import SmartConnect
import pyotp

# Logging setup
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ========================
# CONFIGURATION
# ========================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# AngelOne Credentials
ANGEL_API_KEY = os.getenv("ANGEL_API_KEY")
ANGEL_CLIENT_ID = os.getenv("ANGEL_CLIENT_ID")
ANGEL_PASSWORD = os.getenv("ANGEL_PASSWORD")
ANGEL_TOTP_TOKEN = os.getenv("ANGEL_TOTP_TOKEN")  # For 2FA

# Stock/Index List - Symbol mapping
STOCKS_INDICES = {
    # Indices
    "NIFTY 50": {"symbol": "NIFTY", "token": "99926000", "exchange": "NSE"},
    "NIFTY BANK": {"symbol": "BANKNIFTY", "token": "99926009", "exchange": "NSE"},
    "SENSEX": {"symbol": "SENSEX", "token": "99919000", "exchange": "BSE"},
    
    # Stocks
    "RELIANCE": {"symbol": "RELIANCE-EQ", "token": "2885", "exchange": "NSE"},
    "HDFCBANK": {"symbol": "HDFCBANK-EQ", "token": "1333", "exchange": "NSE"},
    "ICICIBANK": {"symbol": "ICICIBANK-EQ", "token": "4963", "exchange": "NSE"},
    "BAJFINANCE": {"symbol": "BAJFINANCE-EQ", "token": "317", "exchange": "NSE"},
    "INFY": {"symbol": "INFY-EQ", "token": "1594", "exchange": "NSE"},
    "TATAMOTORS": {"symbol": "TATAMOTORS-EQ", "token": "3456", "exchange": "NSE"},
    "AXISBANK": {"symbol": "AXISBANK-EQ", "token": "5900", "exchange": "NSE"},
    "SBIN": {"symbol": "SBIN-EQ", "token": "3045", "exchange": "NSE"},
    "LTIM": {"symbol": "LTIM-EQ", "token": "17818", "exchange": "NSE"},
    "ADANIENT": {"symbol": "ADANIENT-EQ", "token": "25", "exchange": "NSE"},
    "KOTAKBANK": {"symbol": "KOTAKBANK-EQ", "token": "1922", "exchange": "NSE"},
    "LT": {"symbol": "LT-EQ", "token": "11483", "exchange": "NSE"},
    "MARUTI": {"symbol": "MARUTI-EQ", "token": "10999", "exchange": "NSE"},
    "TECHM": {"symbol": "TECHM-EQ", "token": "13538", "exchange": "NSE"},
    "LICI": {"symbol": "LICI-EQ", "token": "11483", "exchange": "NSE"},
    "HINDUNILVR": {"symbol": "HINDUNILVR-EQ", "token": "1394", "exchange": "NSE"},
    "NTPC": {"symbol": "NTPC-EQ", "token": "11630", "exchange": "NSE"},
    "BHARTIARTL": {"symbol": "BHARTIARTL-EQ", "token": "10604", "exchange": "NSE"},
    "POWERGRID": {"symbol": "POWERGRID-EQ", "token": "14977", "exchange": "NSE"},
    "ONGC": {"symbol": "ONGC-EQ", "token": "2475", "exchange": "NSE"},
    "PERSISTENT": {"symbol": "PERSISTENT-EQ", "token": "14299", "exchange": "NSE"},
    "DRREDDY": {"symbol": "DRREDDY-EQ", "token": "881", "exchange": "NSE"},
    "M&M": {"symbol": "M&M-EQ", "token": "2031", "exchange": "NSE"},
    "WIPRO": {"symbol": "WIPRO-EQ", "token": "3787", "exchange": "NSE"},
    "DMART": {"symbol": "DMART-EQ", "token": "17388", "exchange": "NSE"},
    "TRENT": {"symbol": "TRENT-EQ", "token": "1964", "exchange": "NSE"},
}

# ========================
# BOT CODE
# ========================

class AngelOneOptionChainBot:
    def __init__(self):
        self.bot = Bot(token=TELEGRAM_BOT_TOKEN)
        self.running = True
        self.smart_api = None
        self.auth_token = None
        self.refresh_token = None
        self.feed_token = None
        logger.info("Bot initialized successfully")
    
    async def login_to_angelone(self):
        """AngelOne मध्ये login करतो"""
        try:
            logger.info("Logging into AngelOne...")
            
            # SmartConnect object तयार करतो
            self.smart_api = SmartConnect(api_key=ANGEL_API_KEY)
            
            # TOTP generate करतो (2FA साठी)
            totp = pyotp.TOTP(ANGEL_TOTP_TOKEN).now()
            
            # Login करतो
            data = self.smart_api.generateSession(
                clientCode=ANGEL_CLIENT_ID,
                password=ANGEL_PASSWORD,
                totp=totp
            )
            
            if data['status']:
                self.auth_token = data['data']['jwtToken']
                self.refresh_token = data['data']['refreshToken']
                self.feed_token = data['data']['feedToken']
                
                logger.info("✅ AngelOne login successful!")
                return True
            else:
                logger.error(f"❌ Login failed: {data.get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            logger.error(f"Error logging into AngelOne: {e}")
            return False
    
    def get_ltp(self, exchange, symbol, token):
        """Live LTP (Last Traded Price) घेतो"""
        try:
            response = self.smart_api.ltpData(exchange, symbol, token)
            
            if response and response.get('status'):
                ltp_data = response.get('data', {})
                return float(ltp_data.get('ltp', 0))
            
            return 0
            
        except Exception as e:
            logger.error(f"Error getting LTP for {symbol}: {e}")
            return 0
    
    def get_historical_data(self, exchange, symbol, token, display_name):
        """Last 5 days चे सर्व 5-minute candles घेतो"""
        try:
            from datetime import datetime, timedelta
            
            # Last 5 trading days साठी dates
            to_date = datetime.now()
            from_date = to_date - timedelta(days=7)  # 7 days back to ensure 5 trading days
            
            # Historical data params
            params = {
                "exchange": exchange,
                "symboltoken": token,
                "interval": "FIVE_MINUTE",
                "fromdate": from_date.strftime("%Y-%m-%d %H:%M"),
                "todate": to_date.strftime("%Y-%m-%d %H:%M")
            }
            
            logger.info(f"Historical API call for {display_name}: {params}")
            
            response = self.smart_api.getCandleData(params)
            
            if response and response.get('status'):
                candle_data = response.get('data', [])
                
                if candle_data:
                    # Candles तयार करतो
                    candles = []
                    for candle in candle_data:
                        # Format: [timestamp, open, high, low, close, volume]
                        candles.append({
                            'timestamp': candle[0],
                            'open': float(candle[1]),
                            'high': float(candle[2]),
                            'low': float(candle[3]),
                            'close': float(candle[4]),
                            'volume': int(candle[5])
                        })
                    
                    logger.info(f"{display_name}: Returning {len(candles)} candles from last 5 days (5 min)")
                    return candles
                else:
                    logger.warning(f"{display_name}: No candle data received")
                    return None
            else:
                logger.warning(f"{display_name}: API call failed - {response}")
                return None
            
        except Exception as e:
            logger.error(f"Error getting historical data for {display_name}: {e}")
            return None
    
    def create_candlestick_chart(self, candles, symbol, spot_price):
        """Candlestick chart तयार करतो"""
        try:
            # DataFrame तयार करतो
            df_data = []
            for candle in candles:
                timestamp = candle.get('timestamp', '')
                df_data.append({
                    'Date': pd.to_datetime(timestamp) if timestamp else pd.Timestamp.now(),
                    'Open': float(candle.get('open', 0)),
                    'High': float(candle.get('high', 0)),
                    'Low': float(candle.get('low', 0)),
                    'Close': float(candle.get('close', 0)),
                    'Volume': int(float(candle.get('volume', 0)))
                })
            
            df = pd.DataFrame(df_data)
            df.set_index('Date', inplace=True)
            
            # Check if enough data
            if len(df) < 2:
                logger.warning(f"{symbol}: Not enough candles ({len(df)}) for chart")
                return None
            
            # Chart style
            mc = mpf.make_marketcolors(
                up='#26a69a',
                down='#ef5350',
                edge='inherit',
                wick='inherit',
                volume='in'
            )
            
            s = mpf.make_mpf_style(
                marketcolors=mc,
                gridstyle='-',
                gridcolor='#333333',
                facecolor='#1e1e1e',
                figcolor='#1e1e1e',
                gridaxis='both',
                y_on_right=False
            )
            
            # Chart बनवतो
            fig, axes = mpf.plot(
                df,
                type='candle',
                style=s,
                volume=True,
                title=f'\n{symbol} - Last {len(candles)} Candles | Spot: ₹{spot_price:,.2f}',
                ylabel='Price (₹)',
                ylabel_lower='Volume',
                figsize=(12, 8),
                returnfig=True,
                tight_layout=True
            )
            
            # Title customize करतो
            axes[0].set_title(
                f'{symbol} - Last {len(candles)} Candles | Spot: ₹{spot_price:,.2f}',
                color='white',
                fontsize=14,
                fontweight='bold',
                pad=20
            )
            
            # Axes color
            for ax in axes:
                ax.tick_params(colors='white', which='both')
                ax.spines['bottom'].set_color('white')
                ax.spines['top'].set_color('white')
                ax.spines['left'].set_color('white')
                ax.spines['right'].set_color('white')
                ax.xaxis.label.set_color('white')
                ax.yaxis.label.set_color('white')
            
            # Memory buffer मध्ये save करतो
            buf = io.BytesIO()
            fig.savefig(buf, format='png', dpi=100, bbox_inches='tight', facecolor='#1e1e1e')
            buf.seek(0)
            plt.close(fig)
            
            return buf
            
        except Exception as e:
            logger.error(f"Error creating chart for {symbol}: {e}")
            return None
    
    def get_option_chain(self, symbol_name, exchange, token):
        """Option chain data घेतो"""
        try:
            # AngelOne option chain API
            # Note: AngelOne doesn't have direct option chain API like Dhan
            # We need to use searchScrip to find option contracts
            
            params = {
                "exchange": exchange,
                "searchscrip": symbol_name
            }
            
            response = self.smart_api.searchScrip(params)
            
            if response and response.get('status'):
                return response.get('data', [])
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting option chain: {e}")
            return None
    
    def format_option_message(self, symbol, spot_price, candle_count):
        """Simple message format (AngelOne doesn't have direct option chain API)"""
        try:
            msg = f"📊 *{symbol} LIVE DATA*\n"
            msg += f"💰 Spot Price: ₹{spot_price:,.2f}\n"
            msg += f"📈 Candles: {candle_count}\n"
            msg += f"⏰ Time: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}\n\n"
            msg += "_Option chain data coming soon..._"
            
            return msg
            
        except Exception as e:
            logger.error(f"Error formatting message for {symbol}: {e}")
            return None
    
    async def send_option_chain_batch(self, symbols_batch):
        """एका batch चे option chain data + chart पाठवतो"""
        for symbol_key in symbols_batch:
            try:
                info = STOCKS_INDICES[symbol_key]
                symbol = info['symbol']
                token = info['token']
                exchange = info['exchange']
                
                logger.info(f"Fetching data for {symbol_key}...")
                
                # LTP घेतो
                spot_price = self.get_ltp(exchange, symbol, token)
                if spot_price == 0:
                    logger.warning(f"{symbol_key}: LTP नाही मिळाला")
                    continue
                
                # Historical data घेतो (candles साठी)
                logger.info(f"Fetching historical candles for {symbol_key}...")
                candles = self.get_historical_data(exchange, symbol, token, symbol_key)
                
                # Chart तयार करतो
                chart_buf = None
                if candles:
                    logger.info(f"Creating candlestick chart for {symbol_key}...")
                    chart_buf = self.create_candlestick_chart(candles, symbol_key, spot_price)
                
                # Chart पाठवतो (जर available असेल तर)
                if chart_buf:
                    await self.bot.send_photo(
                        chat_id=TELEGRAM_CHAT_ID,
                        photo=chart_buf,
                        caption=f"📊 {symbol_key} - Last {len(candles)} Candles Chart"
                    )
                    logger.info(f"✅ {symbol_key} chart sent")
                    await asyncio.sleep(1)
                
                # Message format करतो
                message = self.format_option_message(
                    symbol_key, 
                    spot_price, 
                    len(candles) if candles else 0
                )
                
                if message:
                    await self.bot.send_message(
                        chat_id=TELEGRAM_CHAT_ID,
                        text=message,
                        parse_mode='Markdown'
                    )
                    logger.info(f"✅ {symbol_key} data sent")
                
                # Rate limit साठी थांबतो
                await asyncio.sleep(2)
                
            except Exception as e:
                logger.error(f"Error processing {symbol_key}: {e}")
                await asyncio.sleep(2)
    
    async def run(self):
        """Main loop - every 5 minutes option chain + chart पाठवतो"""
        logger.info("🚀 Bot started! Logging into AngelOne...")
        
        # AngelOne login करतो
        success = await self.login_to_angelone()
        if not success:
            logger.error("Failed to login to AngelOne. Exiting...")
            return
        
        await self.send_startup_message()
        
        # Symbols ला batches मध्ये divide करतो (5 per batch)
        all_symbols = list(STOCKS_INDICES.keys())
        batch_size = 5
        batches = [all_symbols[i:i+batch_size] for i in range(0, len(all_symbols), batch_size)]
        
        logger.info(f"Total {len(all_symbols)} symbols in {len(batches)} batches")
        
        while self.running:
            try:
                timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
                logger.info(f"\n{'='*50}")
                logger.info(f"Starting update cycle at {timestamp}")
                logger.info(f"{'='*50}")
                
                # प्रत्येक batch process करतो
                for batch_num, batch in enumerate(batches, 1):
                    logger.info(f"\n📦 Processing Batch {batch_num}/{len(batches)}: {batch}")
                    await self.send_option_chain_batch(batch)
                    
                    # Batches मध्ये 5 second gap
                    if batch_num < len(batches):
                        logger.info(f"Waiting 5 seconds before next batch...")
                        await asyncio.sleep(5)
                
                logger.info("\n✅ All batches completed!")
                logger.info("⏳ Waiting 5 minutes for next cycle...\n")
                
                # 5 minutes wait
                await asyncio.sleep(300)
                
            except KeyboardInterrupt:
                logger.info("Bot stopped by user")
                self.running = False
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                await asyncio.sleep(60)
    
    async def send_startup_message(self):
        """Bot सुरू झाल्यावर message पाठवतो"""
        try:
            msg = "🤖 *AngelOne Option Chain Bot Started!*\n\n"
            msg += f"📊 Tracking {len(STOCKS_INDICES)} stocks/indices\n"
            msg += "⏱️ Updates every 5 minutes\n"
            msg += "📈 Features:\n"
            msg += "  • Candlestick Charts (5-min candles)\n"
            msg += "  • Live Spot Prices\n"
            msg += "  • Historical Data (Last 5 days)\n\n"
            msg += "✅ Powered by AngelOne SmartAPI\n"
            msg += "🚂 Deployed on Railway.app\n\n"
            msg += "_Market Hours: 9:15 AM - 3:30 PM (Mon-Fri)_"
            
            await self.bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=msg,
                parse_mode='Markdown'
            )
            logger.info("Startup message sent")
        except Exception as e:
            logger.error(f"Error sending startup message: {e}")


# ========================
# BOT RUN करा
# ========================
if __name__ == "__main__":
    try:
        # Environment variables check
        required_vars = [
            TELEGRAM_BOT_TOKEN, 
            TELEGRAM_CHAT_ID, 
            ANGEL_API_KEY, 
            ANGEL_CLIENT_ID, 
            ANGEL_PASSWORD,
            ANGEL_TOTP_TOKEN
        ]
        
        if not all(required_vars):
            logger.error("❌ Missing environment variables!")
            logger.error("Please set: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, ANGEL_API_KEY, ANGEL_CLIENT_ID, ANGEL_PASSWORD, ANGEL_TOTP_TOKEN")
            exit(1)
        
        bot = AngelOneOptionChainBot()
        asyncio.run(bot.run())
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        exit(1)

# requirements.txt:
# python-telegram-bot==20.7
# requests==2.31.0
# matplotlib==3.7.1
# mplfinance==0.12.10b0
# pandas==2.0.3
# smartapi-python==1.3.0
# pyotp==2.9.0
