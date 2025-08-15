"""
ACL Configuration Reloading Support

This module provides functionality to reload ACL configurations at runtime
without restarting the BBMD.
"""

import asyncio
import logging
from pathlib import Path
from typing import Optional, Callable, Any
from datetime import datetime
import hashlib

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

from .config import ConfigLoader
from .models.acl import ACLConfig

logger = logging.getLogger(__name__)


class ACLFileWatcher(FileSystemEventHandler):
    """Watch ACL configuration file for changes."""
    
    def __init__(self, acl_path: Path, reload_callback: Callable[[ACLConfig], None]):
        """
        Initialize ACL file watcher.
        
        Args:
            acl_path: Path to ACL configuration file
            reload_callback: Function to call with new ACL config when file changes
        """
        self.acl_path = acl_path.resolve()
        self.reload_callback = reload_callback
        self.config_loader = ConfigLoader()
        self._last_hash = self._get_file_hash()
        self._last_reload = datetime.now()
        self._reload_cooldown = 2.0  # seconds
        
    def _get_file_hash(self) -> str:
        """Get hash of file contents."""
        try:
            with open(self.acl_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return ""
    
    def on_modified(self, event):
        """Handle file modification events."""
        if not isinstance(event, FileModifiedEvent):
            return
            
        if Path(event.src_path).resolve() != self.acl_path:
            return
        
        # Check cooldown to avoid multiple reloads
        now = datetime.now()
        if (now - self._last_reload).total_seconds() < self._reload_cooldown:
            return
        
        # Check if content actually changed
        current_hash = self._get_file_hash()
        if current_hash == self._last_hash:
            return
            
        logger.info(f"ACL configuration file changed: {self.acl_path}")
        
        try:
            # Load new configuration
            new_config = self.config_loader.load_acl_config(self.acl_path)
            
            # Validate configuration
            logger.info("Validating new ACL configuration...")
            # ACLConfig validation happens automatically via Pydantic
            
            # Call reload callback
            self.reload_callback(new_config)
            
            # Update state
            self._last_hash = current_hash
            self._last_reload = now
            
            logger.info("ACL configuration reloaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to reload ACL configuration: {e}")


class ACLReloadManager:
    """Manage ACL configuration reloading."""
    
    def __init__(self):
        """Initialize reload manager."""
        self.observer: Optional[Observer] = None
        self.watcher: Optional[ACLFileWatcher] = None
        self._reload_callbacks: list[Callable[[ACLConfig], None]] = []
        
    def add_reload_callback(self, callback: Callable[[ACLConfig], None]) -> None:
        """Add a callback to be called when ACL is reloaded."""
        self._reload_callbacks.append(callback)
        
    def start_watching(self, acl_path: Path) -> None:
        """
        Start watching ACL configuration file for changes.
        
        Args:
            acl_path: Path to ACL configuration file
        """
        if self.observer is not None:
            self.stop_watching()
            
        # Create watcher
        self.watcher = ACLFileWatcher(acl_path, self._on_acl_reload)
        
        # Create observer
        self.observer = Observer()
        self.observer.schedule(self.watcher, str(acl_path.parent), recursive=False)
        self.observer.start()
        
        logger.info(f"Started watching ACL configuration: {acl_path}")
        
    def stop_watching(self) -> None:
        """Stop watching for configuration changes."""
        if self.observer is not None:
            self.observer.stop()
            self.observer.join(timeout=2)
            self.observer = None
            self.watcher = None
            logger.info("Stopped watching ACL configuration")
            
    def _on_acl_reload(self, new_config: ACLConfig) -> None:
        """Handle ACL reload by calling all registered callbacks."""
        for callback in self._reload_callbacks:
            try:
                callback(new_config)
            except Exception as e:
                logger.error(f"Error in ACL reload callback: {e}")
                
    async def reload_acl_manual(self, acl_path: Path) -> ACLConfig:
        """
        Manually reload ACL configuration.
        
        Args:
            acl_path: Path to ACL configuration file
            
        Returns:
            New ACL configuration
            
        Raises:
            Exception if reload fails
        """
        config_loader = ConfigLoader()
        new_config = config_loader.load_acl_config(acl_path)
        
        # Call callbacks
        self._on_acl_reload(new_config)
        
        return new_config