"""
Unit tests for VMExecutor.
"""

from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import subprocess

import pytest

from fastapi_endpoint_detector.executor.vm_executor import VMExecutor, VMExecutorError


class TestVMExecutor:
    """Tests for VMExecutor class."""
    
    def test_init_default_params(self) -> None:
        """Test executor initialization with default parameters."""
        executor = VMExecutor()
        
        assert executor.memory_limit == "512m"
        assert executor.cpu_quota == 50000
        assert executor.timeout == 60
        assert executor.network_disabled is True
    
    def test_init_custom_params(self) -> None:
        """Test executor initialization with custom parameters."""
        executor = VMExecutor(
            memory_limit="1g",
            cpu_quota=100000,
            timeout=120,
            network_disabled=False,
        )
        
        assert executor.memory_limit == "1g"
        assert executor.cpu_quota == 100000
        assert executor.timeout == 120
        assert executor.network_disabled is False
    
    @patch('subprocess.run')
    def test_check_image_exists_true(self, mock_run: Mock) -> None:
        """Test checking if Docker image exists (success case)."""
        mock_run.return_value = Mock(returncode=0)
        
        executor = VMExecutor()
        result = executor.check_image_exists()
        
        assert result is True
        mock_run.assert_called_once()
        assert "docker" in mock_run.call_args[0][0]
        assert "image" in mock_run.call_args[0][0]
        assert "inspect" in mock_run.call_args[0][0]
    
    @patch('subprocess.run')
    def test_check_image_exists_false(self, mock_run: Mock) -> None:
        """Test checking if Docker image exists (not found)."""
        mock_run.return_value = Mock(returncode=1)
        
        executor = VMExecutor()
        result = executor.check_image_exists()
        
        assert result is False
    
    @patch('subprocess.run')
    def test_check_image_exists_timeout(self, mock_run: Mock) -> None:
        """Test checking if Docker image exists (timeout)."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=10)
        
        executor = VMExecutor()
        result = executor.check_image_exists()
        
        assert result is False
    
    @patch('subprocess.run')
    def test_build_image_success(self, mock_run: Mock, tmp_path: Path) -> None:
        """Test building Docker image successfully."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.10")
        
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        
        executor = VMExecutor()
        executor.build_image(dockerfile_path=dockerfile)
        
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "docker" in call_args
        assert "build" in call_args
        assert "-t" in call_args
    
    @patch('subprocess.run')
    def test_build_image_failure(self, mock_run: Mock, tmp_path: Path) -> None:
        """Test building Docker image failure."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.10")
        
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd="docker build",
            stderr="Build failed"
        )
        
        executor = VMExecutor()
        
        with pytest.raises(VMExecutorError) as exc_info:
            executor.build_image(dockerfile_path=dockerfile)
        
        assert "Failed to build Docker image" in str(exc_info.value)
    
    @patch('subprocess.run')
    def test_build_image_timeout(self, mock_run: Mock, tmp_path: Path) -> None:
        """Test building Docker image timeout."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.10")
        
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="docker build",
            timeout=300
        )
        
        executor = VMExecutor()
        
        with pytest.raises(VMExecutorError) as exc_info:
            executor.build_image(dockerfile_path=dockerfile)
        
        assert "timed out" in str(exc_info.value)
    
    def test_build_image_missing_dockerfile(self, tmp_path: Path) -> None:
        """Test building Docker image with missing Dockerfile."""
        dockerfile = tmp_path / "nonexistent" / "Dockerfile"
        
        executor = VMExecutor()
        
        with pytest.raises(VMExecutorError) as exc_info:
            executor.build_image(dockerfile_path=dockerfile)
        
        assert "not found" in str(exc_info.value)
    
    @patch('subprocess.run')
    def test_analyze_in_vm_no_image(self, mock_run: Mock, tmp_path: Path) -> None:
        """Test analyzing in VM without Docker image."""
        mock_run.return_value = Mock(returncode=1)  # Image doesn't exist
        
        app_file = tmp_path / "app.py"
        app_file.write_text("# test")
        
        executor = VMExecutor()
        
        with pytest.raises(VMExecutorError) as exc_info:
            executor.analyze_in_vm(app_path=app_file)
        
        assert "not found" in str(exc_info.value)
    
    @patch('subprocess.run')
    def test_analyze_in_vm_success(self, mock_run: Mock, tmp_path: Path) -> None:
        """Test successful analysis in VM."""
        app_file = tmp_path / "app.py"
        app_file.write_text("# test")
        
        # Mock image exists check
        def run_side_effect(*args, **kwargs):
            cmd = args[0]
            if "inspect" in cmd:
                return Mock(returncode=0)
            else:
                # Docker run command
                return Mock(
                    returncode=0,
                    stdout='{"endpoints": []}',
                    stderr=""
                )
        
        mock_run.side_effect = run_side_effect
        
        executor = VMExecutor()
        result = executor.analyze_in_vm(
            app_path=app_file,
            output_format="json"
        )
        
        assert isinstance(result, dict)
        assert "endpoints" in result
    
    @patch('subprocess.run')
    def test_analyze_in_vm_with_diff(self, mock_run: Mock, tmp_path: Path) -> None:
        """Test analysis in VM with diff file."""
        app_file = tmp_path / "app.py"
        app_file.write_text("# test")
        diff_file = tmp_path / "test.diff"
        diff_file.write_text("diff content")
        
        # Mock image exists and run
        def run_side_effect(*args, **kwargs):
            cmd = args[0]
            if "inspect" in cmd:
                return Mock(returncode=0)
            else:
                return Mock(
                    returncode=0,
                    stdout='{"results": []}',
                    stderr=""
                )
        
        mock_run.side_effect = run_side_effect
        
        executor = VMExecutor()
        result = executor.analyze_in_vm(
            app_path=app_file,
            diff_path=diff_file,
            output_format="json"
        )
        
        assert isinstance(result, dict)
        
        # Check that docker run was called with volume mounts
        docker_run_call = [call for call in mock_run.call_args_list if "run" in str(call)][0]
        call_args = docker_run_call[0][0]
        # When both files are in the same directory, only one volume mount is needed
        assert "-v" in call_args
    
    @patch('subprocess.run')
    def test_analyze_in_vm_security_options(self, mock_run: Mock, tmp_path: Path) -> None:
        """Test that VM uses proper security options."""
        app_file = tmp_path / "app.py"
        app_file.write_text("# test")
        
        def run_side_effect(*args, **kwargs):
            cmd = args[0]
            if "inspect" in cmd:
                return Mock(returncode=0)
            else:
                return Mock(returncode=0, stdout='{}', stderr="")
        
        mock_run.side_effect = run_side_effect
        
        executor = VMExecutor(network_disabled=True)
        executor.analyze_in_vm(app_path=app_file, output_format="json")
        
        # Get the docker run call
        docker_run_call = [call for call in mock_run.call_args_list if "run" in str(call)][0]
        call_args = docker_run_call[0][0]
        
        # Check security options
        assert "--network=none" in call_args
        assert "--read-only" in call_args
        assert "--cap-drop" in call_args
        assert "ALL" in call_args
        assert "--security-opt" in call_args
        assert "no-new-privileges" in call_args
    
    @patch('subprocess.run')
    def test_analyze_in_vm_timeout(self, mock_run: Mock, tmp_path: Path) -> None:
        """Test VM analysis timeout."""
        app_file = tmp_path / "app.py"
        app_file.write_text("# test")
        
        def run_side_effect(*args, **kwargs):
            cmd = args[0]
            if "inspect" in cmd:
                return Mock(returncode=0)
            else:
                raise subprocess.TimeoutExpired(cmd="docker run", timeout=60)
        
        mock_run.side_effect = run_side_effect
        
        executor = VMExecutor(timeout=60)
        
        with pytest.raises(VMExecutorError) as exc_info:
            executor.analyze_in_vm(app_path=app_file)
        
        assert "timed out" in str(exc_info.value)
    
    @patch('subprocess.run')
    def test_analyze_in_vm_container_error(self, mock_run: Mock, tmp_path: Path) -> None:
        """Test VM analysis container execution error."""
        app_file = tmp_path / "app.py"
        app_file.write_text("# test")
        
        def run_side_effect(*args, **kwargs):
            cmd = args[0]
            if "inspect" in cmd:
                return Mock(returncode=0)
            else:
                raise subprocess.CalledProcessError(
                    returncode=1,
                    cmd="docker run",
                    stderr="Container failed"
                )
        
        mock_run.side_effect = run_side_effect
        
        executor = VMExecutor()
        
        with pytest.raises(VMExecutorError) as exc_info:
            executor.analyze_in_vm(app_path=app_file)
        
        assert "Container execution failed" in str(exc_info.value)
