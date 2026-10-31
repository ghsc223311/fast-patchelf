# fast-patchelf

在 **WSL Ubuntu / Linux** 中，把 CTF pwn 題目的動態連結 ELF 配好 libc 和 loader，並在當前目錄生成 `exp.py`。

預設保留原題目，輸出 `<題目名>_patched`、`exp.py` 和 `<題目名>_patched.pwn.json`。已有輸出就停止，不覆寫。預處理不執行題目，也不使用 `ldd`；使用 `readelf` 與 `patchelf` 讀取、修改 ELF。

## 安裝

需要 Bash、Python **3.9+**、GNU binutils 和 patchelf。生成的 exp.py 另需 pwntools；GDB 除錯需 GDB 和 tmux，pwndbg 可自行安裝。

Ubuntu / Debian：

```bash
sudo apt update
sudo apt install git python3 python3-venv binutils patchelf gdb tmux
python3 -m venv ~/.venvs/pwn
source ~/.venvs/pwn/bin/activate
pip install pwntools
```

其他 Linux 請用自己的套件管理器安裝。若只是預處理，不必安裝 pwntools。

若要自動下載 glibc，使用 Python **3.10+** 環境安裝 v2 版 glibc-all-in-one：

```bash
git clone https://github.com/matrix1001/glibc-all-in-one.git ~/glibc-all-in-one-v2
pip install -e ~/glibc-all-in-one-v2
cd ~/glibc-all-in-one-v2
glibc-aio mirror update
```

工具先找 PATH 中的 `glibc-aio`；找不到時，會使用指定 checkout 的 Python 入口，需要在當前 Python 環境安裝其依賴。已下載套件會直接使用，不必連線。

## 用法

先取得此工具，再進入題目資料夾：

```bash
git clone https://github.com/ghsc223311/fast-patchelf.git ~/fast-patchelf
cd ~/ctf/calc

# 1. ELF 同目錄有 libc.so.6 和配對的 ld-linux*.so*：直接使用
#    否則使用該 ELF interpreter 對應的本機 glibc
bash ~/fast-patchelf/pwn-init.sh ./calc

# 2. 指定完整 Ubuntu 套件 ID；缺少時呼叫 glibc-aio download
bash ~/fast-patchelf/pwn-init.sh ./calc \
  --version 2.39-0ubuntu8.9_amd64 \
  --aio-dir ~/glibc-all-in-one-v2

# 3. 題目提供 libc 與 loader，直接指定，不連網
bash ~/fast-patchelf/pwn-init.sh ./calc \
  --libc ./libc.so.6 --ld ./ld-linux-x86-64.so.2

# 4. 自己已有一組相同遠端程序的 libc 洩漏地址
#    以下地址只是格式示例，請替換為實際值
bash ~/fast-patchelf/pwn-init.sh ./calc \
  --leak puts=0x7ffff7e5fbe0 --leak printf=0x7ffff7e346f0 \
  --leak fgets=0x7ffff7e5e440 --leak fputs=0x7ffff7e5d570
```

`--libc`、`--version`、`--leak` 三種方式互斥；`--leak` 可重複。`--ld` 與 `--libc` 一起使用；未指定 `--ld` 時，在該 libc 同目錄找 loader。自動尋找相鄰 libc 時若缺 loader 就停止，不拿系統 loader 混配。

libc.rip 有多個候選時，腳本會列出 ID 並停止。增加洩漏符號，或在原查詢後加 `--select libc6_完整版本_amd64`。選中的版本必須能轉成 glibc-aio 支援的完整套件 ID，且下載 libc 的 Build ID／SHA256 必須符合候選。非 Ubuntu 套件或鏡像已移除的版本，請自行取得配對檔案後用 `--libc`、`--ld`。

搜尋版本可以直接使用上游工具：

```bash
cd ~/glibc-all-in-one-v2
glibc-aio search 2.39-0ubuntu8
```

可選參數：

| 參數 | 用途 |
| --- | --- |
| `-o ./calc_debug` | 改修補 ELF 的輸出路徑 |
| `--exp ./exp_calc.py` | 改範本輸出路徑 |
| `--host example.org --port 31337` | 預填遠端連線設定 |
| `--aio-dir DIR` | 指定 glibc-all-in-one checkout；也可設 `GLIBC_AIO_DIR` |
| `--select ID` | 選擇本次 libc.rip 查詢中的候選 |

自動尋找 checkout 的順序為 `~/glibc-all-in-one-v2`、`~/glibc-all-in-one`。32 位元題目請用 `_i386` 套件。工具會檢查 ELF、libc 和 loader 的位元數、端序及 machine，並檢查 libc 是否提供 ELF 需要的 GLIBC 版本。

## exp.py

```bash
python3 exp.py                            # 本機執行修補副本
python3 exp.py DEBUG                      # 顯示收發資料
python3 exp.py REMOTE HOST=example.org PORT=31337
tmux                                     # 若需要新分割窗除錯，先進入 tmux
python3 exp.py GDB                        # 附加 GDB；也可加 DEBUG
```

範本保留 `s/sl/sa/sla/r/rl/ru/itr/uu32/uu64/uru64`、`libc_sym`、`get_sb` 等快捷函式，並做了以下調整：

- 預設本機模式，遠端模式用 `REMOTE`；埠號預設為可執行的 `0` 佔位值。
- `BIN_PATH`、`LIBC_PATH`、`LD_PATH` 自動填入絕對路徑，含空白、引號的路徑也能生成合法 Python。
- `ru(b'\x7f')` 使用 bytes；`uru64` 僅適合常見 amd64 的六位元組洩漏。
- `leak('puts', leaked_puts)` 明確傳入值；`get_sb(base)` 使用傳入的基址。
- `rl()` 讀一行；`libc_base = 0` 是待填值，洩漏後自行計算。若用本範本的基址函式，請保持 `libc.address = 0`，避免重複加基址。
- 只有 `GDB` 模式附加除錯器。範本不預設 `b main`，適用於 stripped 題目；可自行修改 `commend`。
- 本機 process 清除 `LD_PRELOAD`、`LD_LIBRARY_PATH`、`LD_AUDIT`，避免常見環境設定干擾指定 libc。

## libc 自動偵測的邊界

只有題目 ELF，通常無法知道遠端使用的精確 libc。ELF 內的 `GLIBC_2.xx` 是符號版本需求，並不等於遠端套件版本；腳本不會據此猜一個版本下載。

在本機 pwndbg 中執行：

```text
start
p printf
p puts
p fgets
p fputs
```

取得的是**本機該次執行**載入的地址；要識別遠端 libc，應提供從題目遠端程序洩漏的地址，且須來自同一次映射。IFUNC 的解析後地址、PLT 地址、GOT 槽位本身地址或函式中間的返回地址，不能直接當作相應符號的起始地址。

修補相當於 `patchelf --set-interpreter <ld> --replace-needed <原libc依賴> <libc絕對路徑>`，另外設定 libc 目錄的 RPATH，協助載入同套 glibc 的其他函式庫。原有 RPATH 會保留在後方。有原 RPATH 時要求副本與原 ELF 同目錄。建議所有副本都放在原 ELF 同目錄，以保留 `$ORIGIN` 相依檔的路徑關係。

libc 和 loader 應來自同一套 glibc；對使用者提供的檔案，只做架構與版本需求檢查，無法單憑架構證明兩者配對。絕對路徑修補不具可攜性，移動 libc／loader 或換機器後需重新生成。其他非 libc 依賴不會自動下載；不處理靜態 ELF、musl、自訂 libc 依賴名稱或跨 CPU 模擬執行。ARM 等架構需要自行提供對應 glibc／loader，執行環境另行配置。

## 驗證

```bash
python3 -m unittest discover -s tests -v
# 若有這兩套本機套件，可加測 amd64／i386：
PWN_TEST_AIO_DIR=~/glibc-all-in-one-v2 python3 -m unittest discover -s tests -v
# 額外進行 GDB 四符號地址 → libc.rip → 修補的線上測試：
PWN_TEST_LIVE=1 PWN_TEST_AIO_DIR=~/glibc-all-in-one-v2 python3 -m unittest discover -s tests -v
```

測試需 Linux、gcc、binutils 和 patchelf；真實編譯、修補並執行簡單 C 程式，另驗證不覆寫、原檔不變、特殊路徑、架構不符、靜態 ELF 和 libc.rip 的候選處理。

本次已在 WSL Ubuntu 24.04 通過全部 **18 項測試**，包含真實 `2.39-0ubuntu8.9_amd64`／`i386` 套件，以及 GDB 四個函式地址經 libc.rip 線上查詢後完成修補、執行的流程。下載入口使用模擬下載器驗證；真實套件來自已有快取，沒有重複下載。

## 介面參考

- [glibc-all-in-one v2](https://github.com/matrix1001/glibc-all-in-one)
- [libc.rip API 規格](https://github.com/niklasb/libc-database/blob/master/searchengine/api.yml)
