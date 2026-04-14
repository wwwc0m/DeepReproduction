"""文件说明：PoC 阶段测试。用于校验上下文收集、执行解析和节点重试。"""

from pathlib import Path

from app.schemas.build_artifact import BuildArtifact
from app.schemas.knowledge import KnowledgeModel
from app.schemas.poc_artifact import PoCArtifact
from app.stages import poc as poc_module


def make_knowledge(**overrides):
    payload = {
        "cve_id": "CVE-2022-28805",
        "summary": "demo",
        "vulnerability_type": "heap-overflow",
        "repo_url": "https://example.com/demo.git",
        "vulnerable_ref": "deadbeef",
    }
    payload.update(overrides)
    return KnowledgeModel(**payload)


def make_build(**overrides):
    payload = {
        "dockerfile_content": "FROM ubuntu:20.04\n",
        "build_script_content": "#!/bin/bash\necho build\n",
        "build_success": True,
        "build_logs": "ok",
        "repo_local_path": "/tmp/repo",
        "resolved_ref": "deadbeef",
        "build_system": "make",
        "binary_or_entrypoint": "demo-bin",
        "docker_image_tag": "demo:build",
    }
    payload.update(overrides)
    return BuildArtifact(**payload)


def test_collect_poc_context_uses_build_artifact_and_hints(tmp_path, monkeypatch):
    stage = poc_module.PocStage()
    workspace = tmp_path / "ws"
    repo_dir = workspace / "repo" / "bin"
    repo_dir.mkdir(parents=True)
    (repo_dir / "helper.sh").write_text("#!/bin/bash\necho ok\n", encoding="utf-8")
    (workspace / "repo" / "README.md").write_text("usage: demo-bin --input {payload}\n", encoding="utf-8")
    monkeypatch.setattr(
        stage,
        "_read_patch_diff",
        lambda cve_id: "@@ -1,3 +1,5 @@ static void singlevar(lua_State *L)\n+ if (check_condition) {\n+   luaK_exp2anyregup(fs, &var);\n+ }\n",
    )

    knowledge = make_knowledge(reproduction_hints=["run with --input {payload} --mode crash"], expected_error_patterns=["segmentation fault"])
    build = make_build(repo_local_path=str(workspace / "repo"))

    context = stage.collect_poc_context(knowledge=knowledge, build=build, workspace=str(workspace))

    assert context.target_binary == "demo-bin"
    assert "--input" in context.candidate_cli_flags
    assert "demo-bin" in context.candidate_entrypoints
    assert context.repo_evidence_blocks
    assert "singlevar" in context.patch_changed_functions
    assert "file" in context.inferred_input_modes


def test_plan_poc_prefers_llm_plan_when_available(monkeypatch):
    class FakeResponse:
        def __init__(self, content):
            self.content = content

    class FakeModel:
        def invoke(self, messages):
            return FakeResponse(
                '{"trigger_mode":"cli-file","target_binary":"demo-bin","target_args":["--input","/workspace/artifacts/poc/payloads/llm.txt"],'
                '"environment_variables":{},"payload_filename":"llm.txt","payload_content":"llm\\n","auxiliary_files":{},'
                '"run_command":"demo-bin --input /workspace/artifacts/poc/payloads/llm.txt","expected_exit_code":null,'
                '"expected_stdout_patterns":[],"expected_stderr_patterns":["segmentation fault"],"expected_crash_type":"segmentation fault",'
                '"source_of_truth":"llm","confidence":"high","rationale":"llm plan","dockerfile_override":null,"run_script_override":null}'
            )

    monkeypatch.setattr(poc_module, "build_chat_model", lambda *args, **kwargs: FakeModel())

    stage = poc_module.PocStage()
    knowledge = make_knowledge(expected_error_patterns=["segmentation fault"])
    build = make_build()
    context = poc_module.PocContext(cve_id=knowledge.cve_id)

    plan = stage.plan_poc(knowledge=knowledge, build=build, context=context)

    assert plan.source_of_truth == "llm"
    assert plan.payload_filename == "llm.txt"


def test_plan_poc_falls_back_when_llm_unavailable(monkeypatch):
    monkeypatch.setattr(poc_module, "build_chat_model", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("missing key")))

    stage = poc_module.PocStage()
    knowledge = make_knowledge()
    build = make_build(binary_or_entrypoint="demo-bin")
    context = poc_module.PocContext(cve_id=knowledge.cve_id, target_binary="demo-bin")

    plan = stage.plan_poc(knowledge=knowledge, build=build, context=context)

    assert plan.target_binary == "demo-bin"
    assert plan.source_of_truth in {"heuristic", "dataset_poc"}


def test_heuristic_plan_uses_interpreter_for_script_payload():
    stage = poc_module.PocStage()
    build = make_build(binary_or_entrypoint="")
    context = poc_module.PocContext(cve_id="CVE-2022-9999", inferred_input_modes=["file"])

    target_binary = stage._select_target_binary(build, context, "driver.py")
    trigger_mode = stage._infer_trigger_mode("driver.py", context)

    assert target_binary == "python3"
    assert trigger_mode == "script-driver"


def test_extract_execution_observation_parses_log_blocks():
    stage = poc_module.PocStage()
    logs = (
        "execution_exit_code=139\n"
        "stdout_begin\n"
        "hello\n"
        "stdout_end\n"
        "stderr_begin\n"
        "Segmentation fault\n"
        "stderr_end\n"
    )

    parsed = stage._extract_execution_observation(logs)

    assert parsed["observed_exit_code"] == 139
    assert parsed["observed_stdout"] == "hello"
    assert parsed["observed_crash_type"] == "segmentation fault"


def test_execute_poc_plan_writes_files_and_returns_artifact(tmp_path):
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
                stdout = "target_binary=demo\ntrigger_command=demo poc\nexecution_exit_code=139\nstdout_begin\nok\nstdout_end\nstderr_begin\nsegmentation fault\nstderr_end\n"
                stderr = ""

            return Result()

    stage = poc_module.PocStage(docker_tool=FakeDockerTool())
    paths = poc_module.PocStagePaths(str(tmp_path / "ws"))
    stage._prepare_workspace(paths)
    (paths.repo_dir).mkdir(parents=True, exist_ok=True)

    plan = poc_module.PocPlan(
        target_binary="demo",
        target_args=["/workspace/artifacts/poc/payloads/poc.txt"],
        payload_filename="poc.txt",
        payload_content="boom\n",
        run_command="demo /workspace/artifacts/poc/payloads/poc.txt",
        expected_stderr_patterns=["segmentation fault"],
        expected_crash_type="segmentation fault",
    )

    artifact = stage._execute_poc_plan(
        paths=paths,
        plan_meta={"docker_image_tag": "demo:poc", "base_image_tag": "demo:build"},
        plan=plan,
    )

    assert artifact.execution_success is True
    assert artifact.reproducer_verified is True
    assert Path(paths.run_script).exists()
    assert Path(paths.payloads_dir / "poc.txt").exists()


def test_execute_poc_plan_marks_verified_on_stack_keyword_match(tmp_path):
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
                stdout = "execution_exit_code=1\nstdout_begin\nsinglevar reached\nstdout_end\nstderr_begin\n\nstderr_end\n"
                stderr = ""

            return Result()

    stage = poc_module.PocStage(docker_tool=FakeDockerTool())
    paths = poc_module.PocStagePaths(str(tmp_path / "ws"))
    stage._prepare_workspace(paths)
    paths.repo_dir.mkdir(parents=True, exist_ok=True)

    plan = poc_module.PocPlan(
        target_binary="demo",
        payload_filename="poc.txt",
        payload_content="boom\n",
        run_command="demo /workspace/artifacts/poc/payloads/poc.txt",
        expected_stack_keywords=["singlevar"],
    )

    artifact = stage._execute_poc_plan(
        paths=paths,
        plan_meta={"docker_image_tag": "demo:poc", "base_image_tag": "demo:build"},
        plan=plan,
    )

    assert artifact.matched_stack_keywords == ["singlevar"]
    assert artifact.reproducer_verified is True


def test_poc_node_records_retry_on_unsuccessful_execution(monkeypatch):
    artifact = PoCArtifact(
        poc_filename="poc.txt",
        poc_content="boom\n",
        run_script_content="#!/bin/bash\nexit 0\n",
        execution_success=False,
        execution_logs="not triggered",
    )

    class FakeStage:
        def run(self, knowledge, build, workspace):
            return artifact

    monkeypatch.setattr(poc_module, "PocStage", FakeStage)

    state = {
        "knowledge": make_knowledge(),
        "build": make_build(),
        "workspace": "workspaces/CVE-2022-28805",
        "retry_count": {},
        "stage_history": [],
    }

    result = poc_module.poc_node(state)

    assert result["poc"].execution_success is False
    assert result["retry_count"]["poc"] == 1
    assert result["stage_history"][-1]["status"] == "failed"
