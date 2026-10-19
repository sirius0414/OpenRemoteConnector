# 离线验收样例

这些文件是用户任务输入，不是 ORC 服务依赖。将一个样例目录导出为批准快照，选择已准备的隔离 Python profile，并在 `/work` 的副本执行。所有者先授予具体客户端、设备、环境和有限时长的 grant。

- `text-project`：用字面 argv 运行 `python3 -m unittest discover -s tests`，再运行 `python3 modify.py`；读取产物并提出差异。先拒绝回写；重新申请、核对基线后批准。宿主在批准前应保持原状。
- `offline-tests`：分别运行 `python3 test_pass.py`、`python3 test_failure.py`、`python3 long_running.py`。检查零/非零退出、取消已接收与实际停止的区别、到期停止；HTTP 请求结束不应成为任务取消。
- `text-report`：运行 `python3 report.py`，读取 `report.json` 与 `report.md`。分段读取后提出保存申请；撤销或过期后再次读取应被拒绝。

每次新的执行意图创建新的 UUIDv7；同次重试使用相同 submission ID 和参数。未固定的产物不能提交差异。以上是验收输入和步骤，尚不表示真实 Ubuntu/gVisor 或两种 Agent 客户端验收已通过。
