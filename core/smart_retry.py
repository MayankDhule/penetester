"""
Smart Retry Logic
Automatic retry with exponential backoff and intelligent error handling
"""
import time
import asyncio
from typing import Callable, Any, Optional
from functools import wraps


class RetryConfig:
    """Configuration for retry behavior"""
    
    def __init__(
        self,
        max_retries: int = 3,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
    ):
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt"""
        import random
        
        # Exponential backoff
        delay = min(
            self.initial_delay * (self.exponential_base ** attempt),
            self.max_delay
        )
        
        # Add jitter to prevent thundering herd
        if self.jitter:
            delay = delay * (0.5 + random.random() * 0.5)
        
        return delay


class SmartRetry:
    """Smart retry with exponential backoff"""
    
    # Retryable exceptions
    RETRYABLE_EXCEPTIONS = (
        ConnectionError,
        TimeoutError,
        OSError,
    )
    
    # HTTP status codes that should be retried
    RETRYABLE_STATUS_CODES = {
        408,  # Request Timeout
        429,  # Too Many Requests
        500,  # Internal Server Error
        502,  # Bad Gateway
        503,  # Service Unavailable
        504,  # Gateway Timeout
    }
    
    def __init__(self, config: RetryConfig = None, logger=None):
        self.config = config or RetryConfig()
        self.logger = logger
    
    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """Determine if request should be retried"""
        if attempt >= self.config.max_retries:
            return False
        
        # Check if exception is retryable
        if isinstance(exception, self.RETRYABLE_EXCEPTIONS):
            return True
        
        # Check for specific error messages
        error_msg = str(exception).lower()
        retryable_messages = [
            'timeout',
            'connection reset',
            'connection refused',
            'temporary failure',
            'too many requests',
        ]
        
        return any(msg in error_msg for msg in retryable_messages)
    
    def retry_sync(self, func: Callable, *args, **kwargs) -> Any:
        """Retry synchronous function"""
        last_exception = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                return func(*args, **kwargs)
            
            except Exception as e:
                last_exception = e
                
                if not self.should_retry(e, attempt):
                    raise
                
                delay = self.config.get_delay(attempt)
                
                if self.logger:
                    self.logger.debug(
                        f"[RETRY] Attempt {attempt + 1}/{self.config.max_retries + 1} failed: {e}. "
                        f"Retrying in {delay:.2f}s..."
                    )
                
                time.sleep(delay)
        
        # All retries exhausted
        if self.logger:
            self.logger.error(f"[RETRY] All {self.config.max_retries + 1} attempts failed")
        
        raise last_exception
    
    async def retry_async(self, func: Callable, *args, **kwargs) -> Any:
        """Retry asynchronous function"""
        last_exception = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                return await func(*args, **kwargs)
            
            except Exception as e:
                last_exception = e
                
                if not self.should_retry(e, attempt):
                    raise
                
                delay = self.config.get_delay(attempt)
                
                if self.logger:
                    self.logger.debug(
                        f"[RETRY] Attempt {attempt + 1}/{self.config.max_retries + 1} failed: {e}. "
                        f"Retrying in {delay:.2f}s..."
                    )
                
                await asyncio.sleep(delay)
        
        # All retries exhausted
        if self.logger:
            self.logger.error(f"[RETRY] All {self.config.max_retries + 1} attempts failed")
        
        raise last_exception


def retry(max_retries: int = 3, initial_delay: float = 1.0, logger=None):
    """Decorator for automatic retry"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            config = RetryConfig(max_retries=max_retries, initial_delay=initial_delay)
            retry_handler = SmartRetry(config, logger)
            return retry_handler.retry_sync(func, *args, **kwargs)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            config = RetryConfig(max_retries=max_retries, initial_delay=initial_delay)
            retry_handler = SmartRetry(config, logger)
            return await retry_handler.retry_async(func, *args, **kwargs)
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


class CircuitBreaker:
    """Circuit breaker pattern for failing services"""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        logger=None
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.logger = logger
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'closed'  # closed, open, half-open
    
    def is_open(self) -> bool:
        """Check if circuit breaker is open"""
        if self.state == 'open':
            # Check if recovery timeout has passed
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self.state = 'half-open'
                if self.logger:
                    self.logger.info("[CIRCUIT-BREAKER] Entering half-open state")
                return False
            return True
        
        return False
    
    def record_success(self):
        """Record successful request"""
        if self.state == 'half-open':
            self.state = 'closed'
            self.failure_count = 0
            if self.logger:
                self.logger.info("[CIRCUIT-BREAKER] Circuit closed - service recovered")
    
    def record_failure(self):
        """Record failed request"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = 'open'
            if self.logger:
                self.logger.warning(
                    f"[CIRCUIT-BREAKER] Circuit opened after {self.failure_count} failures"
                )
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Call function with circuit breaker protection"""
        if self.is_open():
            raise Exception("Circuit breaker is open - service unavailable")
        
        try:
            result = func(*args, **kwargs)
            self.record_success()
            return result
        
        except Exception as e:
            self.record_failure()
            raise


class RateLimiter:
    """Rate limiter to respect target rate limits"""
    
    def __init__(self, requests_per_second: float = 10.0, logger=None):
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0
        self.logger = logger
    
    def wait(self):
        """Wait if necessary to respect rate limit"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_interval:
            sleep_time = self.min_interval - time_since_last
            if self.logger:
                self.logger.debug(f"[RATE-LIMITER] Waiting {sleep_time:.3f}s")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    async def wait_async(self):
        """Async wait for rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_interval:
            sleep_time = self.min_interval - time_since_last
            if self.logger:
                self.logger.debug(f"[RATE-LIMITER] Waiting {sleep_time:.3f}s")
            await asyncio.sleep(sleep_time)
        
        self.last_request_time = time.time()



