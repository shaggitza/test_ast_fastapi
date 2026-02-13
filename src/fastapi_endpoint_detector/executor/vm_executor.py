"""
VM-based executor for running analysis in isolated Docker containers.

This module provides secure execution of FastAPI endpoint analysis in
isolated Docker containers to prevent untrusted code from affecting
the host system.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi_endpoint_detector.models.endpoint import Endpoint


class VMExecutorError(Exception):
    """Error during VM execution."""
    pass


class VMExecutor:
    """
    Execute FastAPI endpoint analysis in isolated Docker containers.
    
    This provides strong isolation from the host system using Docker
    containers with resource limits and security constraints.
    """
    
    DOCKER_IMAGE = "fastapi-endpoint-detector:vm"
    
    def __init__(
        self,
        memory_limit: str = "512m",
        cpu_quota: int = 50000,  # 50% of one core
        timeout: int = 60,
        network_disabled: bool = True,
    ) -> None:
        """
        Initialize the VM executor.
        
        Args:
            memory_limit: Memory limit for the container (e.g., "512m").
            cpu_quota: CPU quota for the container (default: 50% of one core).
            timeout: Timeout in seconds for container execution.
            network_disabled: Whether to disable network access in container.
        """
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self.timeout = timeout
        self.network_disabled = network_disabled
    
    def build_image(self, dockerfile_path: Optional[Path] = None) -> None:
        """
        Build the Docker image for VM execution.
        
        Args:
            dockerfile_path: Path to Dockerfile. If not provided, uses default.
            
        Raises:
            VMExecutorError: If image build fails.
        """
        if dockerfile_path is None:
            # Use the default Dockerfile from the project root
            dockerfile_path = Path(__file__).parent.parent.parent.parent / "Dockerfile"
        
        if not dockerfile_path.exists():
            raise VMExecutorError(f"Dockerfile not found at {dockerfile_path}")
        
        # Build the Docker image
        build_cmd = [
            "docker", "build",
            "-t", self.DOCKER_IMAGE,
            "-f", str(dockerfile_path),
            str(dockerfile_path.parent),
        ]
        
        try:
            result = subprocess.run(
                build_cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes to build
            )
        except subprocess.CalledProcessError as e:
            raise VMExecutorError(
                f"Failed to build Docker image: {e.stderr}"
            ) from e
        except subprocess.TimeoutExpired:
            raise VMExecutorError("Docker image build timed out")
    
    def check_image_exists(self) -> bool:
        """
        Check if the Docker image exists.
        
        Returns:
            True if image exists, False otherwise.
        """
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", self.DOCKER_IMAGE],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def analyze_in_vm(
        self,
        app_path: Path,
        diff_path: Optional[Path] = None,
        app_variable: str = "app",
        output_format: str = "json",
    ) -> Any:
        """
        Run analysis in a Docker container.
        
        Args:
            app_path: Path to the FastAPI application.
            diff_path: Optional path to diff file for change analysis.
            app_variable: Name of the FastAPI app variable.
            output_format: Output format (json, yaml, etc.).
            
        Returns:
            Analysis results.
            
        Raises:
            VMExecutorError: If analysis fails or container execution fails.
        """
        # Ensure image exists
        if not self.check_image_exists():
            raise VMExecutorError(
                f"Docker image '{self.DOCKER_IMAGE}' not found. "
                "Run build_image() first or use 'docker build' manually."
            )
        
        # Prepare volume mounts
        app_abs_path = app_path.resolve()
        
        volumes = {
            str(app_abs_path.parent): {
                'bind': '/code',
                'mode': 'ro'  # Read-only
            }
        }
        
        # Prepare command
        if diff_path:
            diff_abs_path = diff_path.resolve()
            volumes[str(diff_abs_path.parent)] = {
                'bind': '/diff',
                'mode': 'ro'
            }
            cmd = [
                "analyze",
                "--app", f"/code/{app_abs_path.name}",
                "--diff", f"/diff/{diff_abs_path.name}",
                "--format", output_format,
                "--app-var", app_variable,
            ]
        else:
            cmd = [
                "list",
                "--app", f"/code/{app_abs_path.name}",
                "--format", output_format,
                "--app-var", app_variable,
            ]
        
        # Build docker run command
        docker_cmd = [
            "docker", "run",
            "--rm",
            "--memory", self.memory_limit,
            "--cpu-quota", str(self.cpu_quota),
        ]
        
        # Add network isolation if requested
        if self.network_disabled:
            docker_cmd.append("--network=none")
        
        # Add read-only root filesystem for security
        docker_cmd.extend(["--read-only", "--tmpfs", "/tmp"])
        
        # Drop all capabilities for security
        docker_cmd.extend(["--cap-drop", "ALL"])
        
        # Add security options
        docker_cmd.extend(["--security-opt", "no-new-privileges"])
        
        # Add volume mounts
        for host_path, mount_info in volumes.items():
            docker_cmd.extend([
                "-v", f"{host_path}:{mount_info['bind']}:{mount_info['mode']}"
            ])
        
        # Add image and command
        docker_cmd.append(self.DOCKER_IMAGE)
        docker_cmd.extend(cmd)
        
        # Execute in container
        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=True,
            )
            
            # Parse output based on format
            if output_format == "json":
                return json.loads(result.stdout)
            else:
                return result.stdout
                
        except subprocess.CalledProcessError as e:
            raise VMExecutorError(
                f"Container execution failed: {e.stderr}"
            ) from e
        except subprocess.TimeoutExpired:
            raise VMExecutorError(
                f"Container execution timed out after {self.timeout} seconds"
            )
        except json.JSONDecodeError as e:
            raise VMExecutorError(
                f"Failed to parse JSON output: {e}"
            ) from e
    
    def list_endpoints_in_vm(
        self,
        app_path: Path,
        app_variable: str = "app",
    ) -> List[Endpoint]:
        """
        List endpoints using VM execution.
        
        Args:
            app_path: Path to the FastAPI application.
            app_variable: Name of the FastAPI app variable.
            
        Returns:
            List of endpoints.
        """
        result = self.analyze_in_vm(
            app_path=app_path,
            app_variable=app_variable,
            output_format="json",
        )
        
        # Parse JSON result into Endpoint objects
        endpoints = []
        if isinstance(result, dict) and "endpoints" in result:
            for ep_data in result["endpoints"]:
                # This would need proper deserialization
                # For now, return the raw result
                pass
        
        return endpoints
