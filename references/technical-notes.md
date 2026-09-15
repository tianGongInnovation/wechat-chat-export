# 微信 4.x 本地数据库解密与导出技术笔记

本文是导出脚本工作所需的底层事实，供排查问题时阅读。

## 库结构与加密

- 数据根目录下每个账号一个文件夹：`wxid_<id>_<后缀>\db_storage\`
- 关键库：
  - `message\message_<n>.db`：消息主体，按时间段分区（编号与时间的对应关系需看数据确认）
  - `contact\contact.db`：联系人（`username/remark/nick_name/alias`）
  - `session\session.db`：会话表 `SessionTable(username, last_timestamp, summary, ...)`
- SQLCipher 4，页 4096，reserve 80：
  - salt = 文件头 `[0:16]`
  - 页 1：加密区 `[16:4016]`，IV `[4016:4032]`，HMAC `[4032:4096]`；其余页加密区 `[0:4016]`
- 派生：
  - `encKey = PBKDF2-HMAC-SHA512(key, salt, 256000, 32)`
  - `macSalt = salt XOR 0x3a`
  - `macKey = PBKDF2-HMAC-SHA512(encKey, macSalt, 2, 32)`
  - 页1 校验：`HMAC-SHA512(macKey, page1[16:4032] + struct.pack('<I',1)) == page1[4032:4096]`
- 每个 `.db` 有各自独立 salt，但同一账号全部库共用同一个 32 字节 key（64 位 hex）。**不同账号目录 key 不同**。

## 消息表与发送者

- 某联系人的消息表名 = `Msg_` + `MD5(对方wxid)` 的小写 hex。
- `Name2Id(user_name, is_session)`：`real_sender_id` 指向其 rowid。
- **发送者映射逐库可能翻转**（不同分库里 rowid1 可能是本人也可能是对方），一律按每个库自己的 Name2Id 解析，禁止硬编码 1/2。
- `local_type` 高 32 位带压缩标记，取其低 16 位即微信标准类型：1文本、3图片、34语音、43视频、47表情、49链接/转账卡片、50通话、10000系统。
- `message_content` 可能以 ZSTD 帧存储（魔数 `28 b5 2f fd`），用 zstandard 直接解压。
- `create_time` 为 Unix 秒（UTC），导出显示按 `UTC+8`。

## 已验证结论（实测 4.1.13.12）

- WAL（`-wal`）帧头被魔改，主库文件本身完整；导出以**主库**为准。会话表最后时间若略晚于主库最后时间，说明少量新消息尚未合并进主库。
- 导出完整性用会话表锚定：`SessionTable.last_timestamp` 应等于导出最大 `create_time`。
- 主库文件在微信运行时被独占锁定，需 `CreateFileW(..., FILE_SHARE_READ|WRITE|DELETE, ...)` 读取（脚本已内置 `shared_read`）。

## 数据库密钥说明

- 密钥是 64 位 hex（32 字节口令）。用任意库第 1 页 HMAC 即可验证密钥是否对应该账号目录。
- 已保存的密钥可能长期有效（实测同一密钥在多次重启后仍能解锁全部库），可复用旧密钥免重复验证。

## 密钥捕获要点（SetDBKey 路线，仅本机使用）

- 微信只在**启动登录早期**调用 `SetDBKey`；登录后/退出登录都不会触发。捕获必须"先关微信 → 组件就绪 → 用户再登录"。
- 捕获组件为 `wx_key.dll`（A 包随包附带；B 包在本机没有时，脚本会完整披露并征求使用者同意后才获取，不同意则终止）。
- 组件导出接口：`InitializeHook(uint32 pid)`、`PollKeyData(char*,int)`、`GetStatusMessage(char*,int,int*)`、`CleanupHook()`、`GetLastErrorMsg()`。
- 捕获到的是 64 位 hex（32 字节口令），只写入本机 `key.txt`，不上传不外传。

## 输出格式约定

- HTML：按天分组、左右气泡（左=对方，右=本人），系统消息居中灰字。
- CSV：`时间,发送人,类型,内容`，UTF-8 with BOM（Excel 可直接打开）。
- 媒体（图片/语音/视频）以 `[图片]/[语音 N 秒]/[视频 N 秒]` 等标签占位；实体文件导出未做。
