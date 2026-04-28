"""文件说明：Schema 测试。用于校验各类 Pydantic 模型的字段约束和序列化行为。"""

from app.schemas.poc_artifact import PoCArtifact


def test_poc_artifact_loads_legacy_payload_without_new_fields():
    """Fix 2-3.D: 旧版 poc_artifact.yaml 缺新增三字段时仍能被加载，
    并采用安全默认值（空 dict / 空 list / 空字符串）。"""

    legacy_payload = {
        "poc_filename": "poc.lua",
        "poc_content": "print('boom')",
        "run_script_content": "#!/bin/bash\nlua poc.lua\n",
    }
    artifact = PoCArtifact(**legacy_payload)

    assert artifact.environment_variables == {}
    assert artifact.expected_stack_keywords == []
    assert artifact.expected_crash_type == ""
