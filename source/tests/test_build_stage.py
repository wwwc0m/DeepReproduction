"""文件说明：Build 阶段测试。用于校验构建系统识别和节点重试语义。"""

from app.schemas.build_artifact import BuildArtifact
from app.schemas.knowledge import KnowledgeModel
from app.stages import build as build_module


def make_knowledge(**overrides):
    payload = {
        "cve_id": "CVE-2022-0000",
        "summary": "demo",
        "vulnerability_type": "heap-overflow",
        "repo_url": "https://example.com/demo.git",
        "vulnerable_ref": "deadbeef",
    }
    payload.update(overrides)
    return KnowledgeModel(**payload)


def test_select_build_system_prefers_repo_scan():
    stage = build_module.BuildStage()
    knowledge = make_knowledge(build_systems=["make"])
    detected_files = ["subdir/CMakeLists.txt", "README.md"]

    assert stage._select_build_system(knowledge, detected_files) == "cmake"


def test_select_build_commands_falls_back_for_unknown():
    stage = build_module.BuildStage()
    knowledge = make_knowledge(build_commands=[])

    commands = stage._select_build_commands(knowledge, "unknown")

    assert commands[-1] == "exit 2"


def test_heuristic_build_plan_prefers_fixed_parent():
    stage = build_module.BuildStage()
    knowledge = make_knowledge(fixed_ref="feedface")
    context = build_module.BuildContext(
        cve_id=knowledge.cve_id,
        repo_url=knowledge.repo_url or "",
        snapshots=[
            build_module.RefSnapshot(label="knowledge_vulnerable", requested_ref="deadbeef", resolved_ref="deadbeef"),
            build_module.RefSnapshot(
                label="fixed_parent",
                requested_ref="beadfeed",
                resolved_ref="beadfeed",
                build_files=["Makefile"],
            ),
        ],
    )

    plan = stage._heuristic_build_plan(knowledge, context, project_name="demo")

    assert plan.chosen_vulnerable_ref == "beadfeed"
    assert plan.build_system == "make"


def test_build_fallback_spec_centralizes_heuristic_defaults():
    stage = build_module.BuildStage()
    knowledge = make_knowledge(
        install_commands=["apt-get install zlib openssl"],
        fixed_ref="feedface",
    )
    context = build_module.BuildContext(
        cve_id=knowledge.cve_id,
        repo_url=knowledge.repo_url or "",
        snapshots=[
            build_module.RefSnapshot(
                label="fixed_parent",
                requested_ref="beadfeed",
                resolved_ref="beadfeed",
                build_files=["CMakeLists.txt"],
            ),
        ],
    )

    spec = stage._build_fallback_spec(knowledge=knowledge, context=context, project_name="demo")

    assert spec.chosen_vulnerable_ref == "beadfeed"
    assert spec.build_system == "cmake"
    assert "cmake --build build -j$(nproc)" in spec.build_commands
    assert "zlib1g-dev" in spec.install_packages
    assert "libssl-dev" in spec.install_packages


def test_build_node_records_retry_on_unsuccessful_build(monkeypatch):
    artifact = BuildArtifact(
        dockerfile_content="FROM ubuntu:20.04\n",
        build_script_content="#!/bin/bash\nexit 2\n",
        build_success=False,
        build_logs="build failed",
    )

    class FakeStage:
        def run(self, knowledge, workspace):
            return artifact

    monkeypatch.setattr(build_module, "BuildStage", FakeStage)

    state = {
        "knowledge": make_knowledge(),
        "workspace": "workspaces/CVE-2022-0000",
        "retry_count": {},
        "stage_history": [],
    }

    result = build_module.build_node(state)

    assert result["build"].build_success is False
    assert result["retry_count"]["build"] == 1
    assert result["stage_history"][-1]["status"] == "failed"


def test_execute_build_plan_uses_script_overrides(tmp_path):
    class FakeDockerTool:
        def build_image(self, request):
            class Result:
                success = True
                exit_code = 0
                stdout = "built"
                stderr = ""

            return Result()

        def run_container(self, request):
            class Result:
                success = True
                exit_code = 0
                stdout = "ran"
                stderr = ""

            return Result()

    stage = build_module.BuildStage(docker_tool=FakeDockerTool())
    paths = build_module.BuildStagePaths(str(tmp_path / "ws"))
    stage._prepare_workspace(paths)
    repo = paths.repo_dir
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "Makefile").write_text("all:\n\techo ok\n", encoding="utf-8")

    plan = build_module.BuildPlan(
        chosen_vulnerable_ref="deadbeef",
        build_system="make",
        install_packages=["gcc", "make"],
        build_commands=["make"],
        dockerfile_override="FROM ubuntu:22.04\n",
        build_script_override="#!/bin/bash\necho custom\n",
    )
    artifact = stage._execute_build_plan(
        repo_path=repo,
        paths=paths,
        plan_meta={
            "repo_url": "https://example.com/demo.git",
            "project_name": "demo",
            "project_dir_name": "demo",
            "docker_image_tag": "demo:latest",
        },
        build_plan=plan,
        resolved_ref="deadbeef",
    )

    assert artifact.dockerfile_content == "FROM ubuntu:22.04\n"
    assert artifact.build_script_content == "#!/bin/bash\necho custom\n"


def test_classify_failure_kind_distinguishes_docker_and_container_failures():
    stage = build_module.BuildStage()

    docker_build_log = "image_build_success=False\nimage_build_exit_code=1\n"
    container_run_log = (
        "image_build_success=True\nimage_build_exit_code=0\n\n"
        "container_run_success=False\ncontainer_run_exit_code=2\n"
    )

    assert stage._classify_failure_kind(docker_build_log) == "docker_build"
    assert stage._classify_failure_kind(container_run_log) == "container_run"


def test_normalize_build_plan_preserves_required_docker_packages(tmp_path):
    stage = build_module.BuildStage()
    repo = tmp_path / "repo"
    repo.mkdir()

    plan = build_module.BuildPlan(
        chosen_vulnerable_ref="deadbeef",
        build_system="make",
        install_packages=["gcc", "make"],
        build_commands=["make"],
    )

    normalized = stage._normalize_build_plan(repo, plan)

    assert "git" in normalized.install_packages
    assert "ca-certificates" in normalized.install_packages


def test_normalize_build_plan_repairs_dockerfile_override_without_required_packages(tmp_path):
    stage = build_module.BuildStage()
    repo = tmp_path / "repo"
    repo.mkdir()

    plan = build_module.BuildPlan(
        chosen_vulnerable_ref="deadbeef",
        build_system="make",
        install_packages=["gcc", "make"],
        build_commands=["make"],
        dockerfile_override=(
            "FROM ubuntu:20.04\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends gcc make && apt-get clean\n"
        ),
    )

    normalized = stage._normalize_build_plan(repo, plan)

    assert "git" in normalized.install_packages
    assert "ca-certificates" in normalized.install_packages
    assert "git" in normalized.dockerfile_override
    assert "ca-certificates" in normalized.dockerfile_override


def test_default_make_install_packages_include_ca_certificates():
    stage = build_module.BuildStage()
    knowledge = make_knowledge()

    packages = stage._select_install_packages("make", knowledge)

    assert "git" in packages
    assert "ca-certificates" in packages
