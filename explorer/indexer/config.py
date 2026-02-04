"""
DSV Block Explorer Indexer Configuration
"""
import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    # Database
    db_host: str = os.getenv("DB_HOST", "localhost")
    db_port: int = int(os.getenv("DB_PORT", "5432"))
    db_name: str = os.getenv("DB_NAME", "dsv_explorer")
    db_user: str = os.getenv("DB_USER", "dsv_explorer")
    db_password: str = os.getenv("DB_PASSWORD", "")
    
    # Redis
    redis_host: str = os.getenv("REDIS_HOST", "localhost")
    redis_port: int = int(os.getenv("REDIS_PORT", "6379"))
    redis_db: int = int(os.getenv("REDIS_DB", "0"))
    
    # Node RPC
    rpc_url: str = os.getenv("RPC_URL", "http://127.0.0.1:8332")
    rpc_auth: str = os.getenv("RPC_AUTH", "")
    
    # Indexer settings
    batch_size: int = int(os.getenv("BATCH_SIZE", "100"))
    poll_interval: int = int(os.getenv("POLL_INTERVAL", "1"))
    reorg_depth: int = int(os.getenv("REORG_DEPTH", "100"))
    
    # Metrics
    metrics_port: int = int(os.getenv("METRICS_PORT", "9100"))
    
    @property
    def db_dsn(self) -> str:
        return f"host={self.db_host} port={self.db_port} dbname={self.db_name} user={self.db_user} password={self.db_password}"
    
    @property
    def redis_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"


config = Config()

