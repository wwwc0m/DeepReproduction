"""文件说明：Docker 工具测试。用于校验镜像构建、容器执行和日志采集相关能力。"""

from app.tools import docker_tools as docker_module
from app.tools.process_tools import ProcessResult


def test_build_image_uses_explicit_build_args_only():
    captured = {}

    class FakeProcessTool:
        def run(self, request):
            captured["command"] = request.command
            return ProcessResult(success=True, exit_code=0, stdout="ok", stderr="")

    tool = docker_module.DockerTool(process_tool=FakeProcessTool())
    tool.build_image(
        docker_module.DockerBuildRequest(
            workspace="/tmp/ws",
            dockerfile_path="/tmp/ws/Dockerfile",
            image_tag="demo:latest",
            build_args={"DEMO_FLAG": "enabled"},
        )
    )

    command = captured["command"]
    assert "--build-arg" in command
    assert "DEMO_FLAG=enabled" in command


def test_run_container_uses_explicit_environment_only():
    captured = {}

    class FakeProcessTool:
        def run(self, request):
            captured["command"] = request.command
            return ProcessResult(success=True, exit_code=0, stdout="ok", stderr="")

    tool = docker_module.DockerTool(process_tool=FakeProcessTool())
    tool.run_container(
        docker_module.DockerRunRequest(
            image_tag="demo:latest",
            workspace="/tmp/ws",
            command=["bash", "-lc", "env"],
            environment={"DEMO_ENV": "enabled"},
        )
    )

    command = captured["command"]
    assert "-e" in command
    assert "DEMO_ENV=enabled" in command
