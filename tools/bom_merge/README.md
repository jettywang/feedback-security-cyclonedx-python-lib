# CycloneDX 组件记录合并判据（基于 cyclonedx-python-lib 现有模型）

适用场景：汇总服务收到多份内存 BOM（源码分析、成品扫描、重复扫描），其中两条
组件记录的 PURL 相同但文件哈希不同。本目录给出字段语义说明、可执行的合并判据、
冲突的标准字段表示，以及带具体哈希和证据的演示与测试。**不引入任何新的包标识
标准**，只使用库已有的 `purl` / `cpe` / `group+name+version` / `hashes` /
`omniborIds` / `swhids` / `bom-ref` / `evidence` / `properties` 字段。

## 1. 字段在“组件实例判定”中的角色

结论先行：**PURL 等坐标只能定位“哪个包的哪个版本”，哈希类字段才能定位“观察到的
具体构建产物（实例）”，`bom-ref` 只是文档内的局部引用名。**

| 库字段（模型位置） | 能确定什么 | 不能确定什么 |
| --- | --- | --- |
| `Component.purl`（`model/component.py:1407`） | 包坐标：type/namespace/name/version/qualifiers 的规范化字符串；`PackageURL` 相等比较含 qualifiers，大小写与 `%2f` 等会被规范化 | 同一版本可对应多个构建产物（重打包、不同编译选项、供应链篡改），PURL 不随字节内容变化 |
| `Component.cpe`（`model/component.py:1390`） | 厂商/产品/版本坐标 | 同样不绑定字节内容；CPE 粒度通常比 PURL 更粗 |
| `Component.group` + `name` + `version`（`model/component.py:1210` 起） | 没有 PURL/CPE 时的兜底坐标 | 仅为声明式坐标，无实例语义 |
| `Component.hashes`：`HashType(alg, content)`（`model/__init__.py:376`，属性在 `model/component.py:1335`） | 对被观察构件的内容指纹；`(算法, 摘要值)` 一致是“同一构件实例”的强证据；同一算法下值不同即实例冲突 | 哈希可能缺失；不同算法之间不能互相比较，只能同算法比对 |
| `Component.omnibor_ids` / `swhids`（`model/component.py:1429`、`:1450`） | 构件级内容标识，语义上与哈希同级，可作为补充实例证据 | 生成成本高，多数扫描器不提供 |
| `Component.swid`（`model/component.py:1473`） | 软件标签，偏发布/许可坐标 | 不保证随每次构建变化，不做实例键 |
| `Component.bom_ref`（`model/bom_ref.py:32`） | **单份 BOM 内**的引用标签，用于依赖图、evidence.tools 等局部链接；库要求其在 BOM 内唯一（`contrib/bom/utils.py:37` 的 `BomRefDiscriminator`） | 跨 BOM 没有稳定性：两份 BOM 可以对同一构件使用不同 bom-ref，也可能对不同构件使用相同字符串。禁止跨文档当合并键 |
| `Component.evidence`（`model/component_evidence.py:640`） | 记录身份结论（`Identity.field` 枚举显式包含 `purl`、`hash` 等，见 `:41`）、分析技术（含 `hash-comparison`、`manifest-analysis`）、置信度、出现位置 `Occurrence`、所用工具 | 是“证据与结论”的容器，不是新的标识；合并时用于保留多份说法而不是选一个赢家 |
| `Bom.serial_number` + `Bom.version`（`model/bom.py:427`） | 标识**文档**及其修订版，用于溯源某条记录来自哪份清单 | 不标识组件本身 |

库自身的行为也印证了这一点：`Component.__eq__`（`model/component.py:1735`）把
`bom_ref.value` 与 `hashes` 都纳入比较——PURL 相同但哈希不同的两个 `Component`
**不相等**。因此直接把记录塞进同一个 `SortedSet` 不会去重，必须由汇总逻辑显式
分层判定。

### 判定分层

1. **坐标层（package coordinates）**：规范化 PURL 字符串 → CPE →
   `(group, name, version)`。坐标一致只说明“指向同一个包版本”。
2. **实例层（component instance）**：哈希集合（以及 OmniBOR/SWHID，若有）。
   - 同算法摘要值全部一致 → 同一构件实例的重复观察。
   - 同算法出现不同摘要值 → 坐标相同但实例不同（不同构建/重打包/疑似篡改），必须并列保留并报冲突。
   - 双方都没有哈希 → 无法证明是同一实例，状态为“未决”，禁止宣称去重成功。
3. **文档层（local reference）**：`bom-ref`、BOM serial/version 仅做溯源，不参与匹配。

## 2. 合并判据（可执行规则）

实现见 `merge.py` 的 `merge_boms()`，输入为内存中的 `Bom` 对象列表，不修改输入：

1. 对每个 `Component` 计算坐标键 `coordinate_key()`：优先 `str(purl)`，其次 `cpe`，最后 `group/name@version`；哈希、bom-ref、evidence、properties 一律不进键。
2. 按坐标键分组，组内对每条记录取哈希签名 `_hash_signature()`（按算法名排序的 `(alg, 小写content)` 元组）。
3. 组内判定：
   - 所有记录都没有哈希 → `UNRESOLVED`（冲突类型 `missing-hash`）。
   - 存在哈希，且任一算法在不同记录中出现多个值 → `HASH_CONFLICT`（冲突类型 `hash-mismatch`），`HashConflict` 逐算法列出全部观察值。
   - 存在哈希且无冲突，仅一条记录 → `SINGLE`；多条记录 → `DUPLICATE`（同一实例的重复扫描，合并为一条）。
   - 部分记录缺哈希时，不丢失无哈希观察：仍由有哈希的记录决定实例判定，无哈希记录保留在 `observations` 溯源里。
4. 输出 `MergedComponent`：每个坐标组一个合并后的 `Component`，哈希取并集（库的 `SortedSet` 自动去重），evidence 原样汇总并补充冲突身份条目，溯源信息放在 `SourceObservation`（BOM serial/version、原始 bom-ref、哈希、occurrence、工具）。

PURL qualifiers 的处理：默认用完整规范化 PURL 分组（`PackageURL` 相等性含
qualifiers）；若业务确认 qualifiers 只反映仓库差异、不代表不同产物，可显式使用
`purl_without_qualifiers()` 归一化——这是调用方的策略选择，函数名让该选择显式
可见，原始 PURL 仍保留在记录上。

## 3. 冲突如何表示（只用现有字段）

- `hash-mismatch`：合并组件保留全部冲突哈希；为每个冲突摘要追加一条
  `evidence.identity`，`field=IdentityField.HASH`、`concludedValue="算法:值"`、
  `methods=[Method(technique=HASH_COMPARISON, confidence=1, value=...)]`，
  让消费方看到所有观察值，而不是二选一。
- `missing-hash`：追加 `field=PURL`、`confidence=0`、技术为
  `MANIFEST_ANALYSIS` 的 identity，明确“只有坐标证据，无法证明实例相同”。
- 机器可读的状态账本写入标准 `properties`（命名空间
  `cyclonedx-python-lib.tools.bom-merge:*`，含 `status`、`conflict`、
  `observation-count`、每算法的 `hash-conflict:<alg>`）；`properties` 本就允许
  同名多值，不需要扩展 schema。
- 合并组件使用新的确定性 `bom-ref`（`merged/<kind>:<坐标>`），原始 bom-ref 保存在
  `SourceObservation.bom_ref` 中，避免跨 BOM 的 bom-ref 碰撞污染依赖引用。

## 4. 三个内存 BOM 场景（具体哈希与证据）

`demo.py` 构造三份 BOM（源码分析器 + 两次成品扫描），运行：

```bash
.venv/bin/python -m tools.bom_merge.demo
```

| 场景 | 坐标 | 哈希证据 | 合并输出 |
| --- | --- | --- | --- |
| 重复扫描 | `pkg:npm/acme/widget@4.2.1`（源码分析 + 扫描1） | 两份 SHA-256 均为 `9f2c7a1d…4e7c` | `duplicate`，一个实例，两条 observations |
| 同版本不同构建 | 同一 PURL（扫描2） | SHA-256 为 `17ab33e0…c2d1` | `hash-conflict`，两个哈希并列 + 两条 hash identity + 冲突 property |
| 缺哈希 | `pkg:npm/lodash@4.17.21`（两份记录均无哈希） | 无 | `unresolved`/`missing-hash`，confidence=0 的 purl identity |
| 多算法一致（对照） | `pkg:pypi/urllib3@2.2.1` | SHA-256 `ee0b1e91…a5f8` 与 SHA-1 `d8b39f2c7a1e46c0` 两份一致 | `duplicate`，哈希并集去重 |

## 5. 测试

```bash
.venv/bin/python -m pytest tests/test_bom_merge.py -v
```

覆盖：重复扫描去重、同 PURL 异哈希冲突、多算法下仅冲突算法上报、全缺哈希未决、
部分缺哈希、单条记录、bom-ref 不作为键、坐标键优先级与回退、不同坐标隔离、
三向哈希冲突、合并结果可序列化为 CycloneDX JSON 1.6、输入 BOM 不被修改。

## 6. 文件

- `merge.py`：合并引擎与数据类（`MergeStatus`、`ConflictKind`、`HashConflict`、
  `SourceObservation`、`MergedComponent`、`merge_boms()`、`to_bom()`）。
- `demo.py`：带具体哈希/evidence 的可运行场景与 JSON 序列化输出。
- `../../tests/test_bom_merge.py`：14 条 pytest 用例。
