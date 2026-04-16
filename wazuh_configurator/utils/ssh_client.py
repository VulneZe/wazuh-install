"""
SSH Client for Remote Wazuh Configuration
Provides secure SSH connections for multi-machine deployments
"""

import paramiko
from typing import Optional, Dict, List, Tuple
import os
import logging
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class SSHCredentials:
    """SSH connection credentials"""
    host: str
    username: str
    port: int = 22
    password: Optional[str] = None
    key_file: Optional[str] = None
    key_passphrase: Optional[str] = None
    
    def __post_init__(self):
        if not self.password and not self.key_file:
            raise ValueError("Either password or key_file must be provided")


class SSHClient:
    """SSH client for remote Wazuh configuration"""
    
    def __init__(self, credentials: SSHCredentials):
        self.credentials = credentials
        self.client: Optional[paramiko.SSHClient] = None
        self._connected = False
    
    def connect(self) -> bool:
        """Establish SSH connection"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if self.credentials.key_file:
                self.client.connect(
                    hostname=self.credentials.host,
                    username=self.credentials.username,
                    port=self.credentials.port,
                    key_filename=self.credentials.key_file,
                    passphrase=self.credentials.key_passphrase,
                    timeout=30,
                    allow_agent=False,
                    look_for_keys=False
                )
            else:
                self.client.connect(
                    hostname=self.credentials.host,
                    username=self.credentials.username,
                    port=self.credentials.port,
                    password=self.credentials.password,
                    timeout=30,
                    allow_agent=False,
                    look_for_keys=False
                )
            
            self._connected = True
            logger.info(f"SSH connected to {self.credentials.host}:{self.credentials.port}")
            return True
            
        except paramiko.AuthenticationException as e:
            logger.error(f"SSH authentication failed: {e}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected SSH error: {e}")
            return False
    
    def disconnect(self):
        """Close SSH connection"""
        if self.client and self._connected:
            self.client.close()
            self._connected = False
            logger.info(f"SSH disconnected from {self.credentials.host}")
    
    def execute_command(self, command: str, timeout: int = 300) -> Tuple[int, str, str]:
        """Execute a command on the remote host"""
        if not self._connected:
            raise RuntimeError("SSH client not connected")
        
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            logger.debug(f"SSH command executed: {command}")
            logger.debug(f"Exit code: {exit_code}")
            
            return exit_code, output, error
            
        except paramiko.SSHException as e:
            logger.error(f"SSH command execution error: {e}")
            return -1, "", str(e)
        except Exception as e:
            logger.error(f"Unexpected command execution error: {e}")
            return -1, "", str(e)
    
    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload a file to the remote host"""
        if not self._connected:
            raise RuntimeError("SSH client not connected")
        
        try:
            sftp = self.client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            logger.info(f"File uploaded: {local_path} -> {remote_path}")
            return True
            
        except Exception as e:
            logger.error(f"File upload error: {e}")
            return False
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download a file from the remote host"""
        if not self._connected:
            raise RuntimeError("SSH client not connected")
        
        try:
            sftp = self.client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            logger.info(f"File downloaded: {remote_path} -> {local_path}")
            return True
            
        except Exception as e:
            logger.error(f"File download error: {e}")
            return False
    
    def file_exists(self, remote_path: str) -> bool:
        """Check if a file exists on the remote host"""
        if not self._connected:
            raise RuntimeError("SSH client not connected")
        
        try:
            sftp = self.client.open_sftp()
            try:
                sftp.stat(remote_path)
                sftp.close()
                return True
            except IOError:
                sftp.close()
                return False
                
        except Exception as e:
            logger.error(f"File existence check error: {e}")
            return False
    
    def read_file(self, remote_path: str) -> Optional[str]:
        """Read a file from the remote host"""
        if not self._connected:
            raise RuntimeError("SSH client not connected")
        
        try:
            sftp = self.client.open_sftp()
            with sftp.file(remote_path, 'r') as f:
                content = f.read().decode('utf-8')
            sftp.close()
            logger.debug(f"File read: {remote_path}")
            return content
            
        except Exception as e:
            logger.error(f"File read error: {e}")
            return None
    
    def write_file(self, remote_path: str, content: str) -> bool:
        """Write content to a file on the remote host"""
        if not self._connected:
            raise RuntimeError("SSH client not connected")
        
        try:
            sftp = self.client.open_sftp()
            with sftp.file(remote_path, 'w') as f:
                f.write(content)
            sftp.close()
            logger.info(f"File written: {remote_path}")
            return True
            
        except Exception as e:
            logger.error(f"File write error: {e}")
            return False
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
