# message_broker.py
# Decoupled Message Broker supporting Redis Pub/Sub and In-Memory Queue Fallback

import os
import json
import threading
import queue

# Try importing redis
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

class MessageBroker:
    """Decoupled broker enabling sniffer events to be routed asynchronously to the SocketIO client."""
    def __init__(self):
        self.redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        self.redis_client = None
        self.local_queue = queue.Queue()
        self.is_redis_active = False
        
        if REDIS_AVAILABLE:
            try:
                # Try connecting to Redis with a short timeout to prevent startup hangs
                self.redis_client = redis.Redis.from_url(
                    self.redis_url, 
                    socket_timeout=1.0, 
                    socket_connect_timeout=1.0
                )
                self.redis_client.ping()
                self.is_redis_active = True
                print(f"[*] Decoupled Message Broker initialized using Redis at {self.redis_url}")
            except Exception as e:
                print(f"[WARNING] Redis connection failed, falling back to In-Memory Pub/Sub: {e}")
                self.redis_client = None
                self.is_redis_active = False
        else:
            print("[*] Redis library not installed, using In-Memory Pub/Sub fallback.")

    def publish(self, channel: str, message: dict):
        """Publishes a JSON payload to a channel."""
        json_data = json.dumps(message)
        if self.is_redis_active and self.redis_client:
            try:
                self.redis_client.publish(channel, json_data)
                return
            except Exception as e:
                print(f"[WARNING] Failed to publish to Redis, routing to fallback queue: {e}")
                self.is_redis_active = False
        
        # Local fallback queue
        self.local_queue.put((channel, json_data))

    def start_subscriber(self, channel: str, callback):
        """Starts a background thread that listens to a channel and executes a callback."""
        def subscriber_loop():
            # If Redis is active, try to consume from Redis Pub/Sub
            if self.is_redis_active and self.redis_client:
                try:
                    pubsub = self.redis_client.pubsub()
                    pubsub.subscribe(channel)
                    print(f"[*] Redis Subscriber worker listening on channel: {channel}")
                    for message in pubsub.listen():
                        if message['type'] == 'message':
                            try:
                                payload = json.loads(message['data'].decode('utf-8'))
                                callback(payload)
                            except Exception as e:
                                print(f"[ERROR] Error executing Redis subscriber callback: {e}")
                except Exception as e:
                    print(f"[WARNING] Redis subscriber connection lost: {e}")
                    self.is_redis_active = False
            
            # Local fallback queue consumer
            print(f"[*] Local Subscriber worker listening on channel: {channel}")
            while True:
                try:
                    chan, data = self.local_queue.get()
                    if chan == channel:
                        try:
                            payload = json.loads(data)
                            callback(payload)
                        except Exception as e:
                            print(f"[ERROR] Error executing local subscriber callback: {e}")
                    self.local_queue.task_done()
                except Exception as e:
                    print(f"[ERROR] Error in local subscriber loop: {e}")

        t = threading.Thread(target=subscriber_loop, daemon=True)
        t.start()
        return t

# Singleton instance of the broker
broker = MessageBroker()
