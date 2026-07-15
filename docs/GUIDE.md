# GG 导出与导入指南

## 1. 安装 GameGuardian

官网：https://gameguardian.net/forum/files/file/2-gameguardian/  
装到雷电后，设置里把语言改为简体中文。

## 2. 找到「改了会动」的地址

1. GG 附加游戏进程（不是雷电 exe）  
2. 搜索数值 → 改变 → 缩小  
3. 修改候选，确认**界面跟着变**  
4. 保存到地址列表

## 3. 导出

### 地址列表

在地址列表界面导出/复制为文本（含 `0x...` 行即可）。

### 指针搜索

对生效地址做指针搜索 → 导出结果文本。  
建议**重启游戏后再搜/再导 1～2 份**，交给本工具交叉。

## 4. 导入本工具

- GUI：离线分析 → 添加文件 → 开始分析 → 导出全部  
- CLI：`python -m gg_base_analyzer analyze a.txt b.txt --game mygame -o out`

## 5. 在线搜链（可选）

需 Frida + 模拟器 frida-server。  
填写包名与生效地址后点「开始在线搜索」。
